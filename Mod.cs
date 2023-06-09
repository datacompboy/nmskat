﻿using Reloaded.Mod.Interfaces;
using nmskat.Template;
using nmskat.Configuration;
using System.Runtime.InteropServices;
using System.Diagnostics;
using Reloaded.Memory.Sigscan.Definitions;
using CallingConventions = Reloaded.Hooks.Definitions.X64.CallingConventions;
using Reloaded.Hooks.Definitions;
using Reloaded.Hooks.Definitions.Enums;
using Reloaded.Hooks;
using Reloaded.Memory;
using Reloaded.Memory.Interfaces;
using Reloaded.Hooks.Definitions.X64;
using System.ComponentModel;

namespace nmskat;

/// <summary>
/// Your mod logic goes here.
/// </summary>
public class Mod : ModBase // <= Do not Remove.
{
    #region Standard Mod Variables
    /// <summary>
    /// Provides access to the mod loader API.
    /// </summary>
    private readonly IModLoader _modLoader;

    /// <summary>
    /// Provides access to the Reloaded.Hooks API.
    /// </summary>
    /// <remarks>This is null if you remove dependency on Reloaded.SharedLib.Hooks in your mod.</remarks>
    private readonly IReloadedHooks? _hooks;

    /// <summary>
    /// Provides access to the Reloaded logger.
    /// </summary>
    private readonly ILogger _logger;

    /// <summary>
    /// Entry point into the mod, instance that created this class.
    /// </summary>
    private readonly IMod _owner;

    /// <summary>
    /// Provides access to this mod's configuration.
    /// </summary>
    private Config _configuration;

    /// <summary>
    /// The configuration of the currently executing mod.
    /// </summary>
    private readonly IModConfig _modConfig;
    #endregion


    #region KAT SDK API
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct katQuaternion
    {
        public float x;
        public float y;
        public float z;
        public float w;

        public System.Numerics.Quaternion ToQuaternion()
        {
            return new System.Numerics.Quaternion(x, y, z, w);
        }
        public float GetAngle()
        {
            // Simplified version of (Quaternion(vector(0, -1, 0), 90degree) * katQuaternion).ToAngle()
            // works for real KatWalk C2+ (for some reason, has issue with simulator from the SDK...)
            return 2.0f * (float)Math.Acos(0.707106781186547524401 * (w + y));
        }
    };

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct katVector3
    {
        public float x;
        public float y;
        public float z;
    };

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1, Size = 384)]
    private unsafe struct KATTreadMillMemoryData
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string deviceName;
        public byte connected; // 1-byte Bool, https://stackoverflow.com/questions/32110152/c-sharp-marshalling-bool
        public double lastUpdateTimePoint;
        public katQuaternion bodyRotationRaw;
        public katVector3 moveSpeed;
    };

    [Reloaded.Hooks.Definitions.X64.Function(CallingConventions.Microsoft)]
    private delegate void FunGetWalkStatus(out KATTreadMillMemoryData result, nuint treadmill);

    /// <summary>
    /// Handle of KATNativeSDK.dll
    /// </summary>
    private nuint hKatDll;

    /// <summary>
    /// Address of GetWalkStatus function from Kat SDK
    /// </summary>
    private static Reloaded.Hooks.Definitions.IFunction<FunGetWalkStatus>? fGetWalkStatus;

    /// <summary>
    /// GC-protected wrapper for generated GetWalkStatus adapter wrapper
    /// </summary>
    private static FunGetWalkStatus? GetWalkStatusWrapper;

    /// <summary>
    /// Try Load KATNativeSDK
    /// </summary>
    /// <returns></returns>
    private bool LoadKatNative()
    {
        hKatDll = LoadLibraryW("KATNativeSDK.dll");
        _logger.WriteLine($"hKatDll = {hKatDll}");
        if (hKatDll == 0)
        {
            _logger.WriteLine("Can't load KATNativeSDK.dll");
            return false;
        }

        var addrGetWalkStatus = GetProcAddress(hKatDll, "GetWalkStatus");
        _logger.WriteLine($"addrGetWalkStatus = {addrGetWalkStatus}");
        if (addrGetWalkStatus == 0)
        {
            _logger.WriteLine("Can't find address of GetWalkStatus");
            return false;
        }

        fGetWalkStatus = _hooks!.CreateFunction<FunGetWalkStatus>((long)addrGetWalkStatus);
        GetWalkStatusWrapper = fGetWalkStatus.GetWrapper();

        return true;
    }
    #endregion


    #region Hook and installer
    /// <summary>
    /// Incremental turn accumulator to avoid long time drift
    /// </summary>
    private static float _lastAngle = 0.0f;

    /// <summary>
    /// Latest computed difference between current treadmill direction and last-known direction.
    /// 
    /// Stored as a pointer to an allocated memory, so injected hook code can trivially read it.
    /// </summary>
    private static unsafe float* _angleDiff = (float*)Marshal.AllocHGlobal(sizeof(float));

    [Function(CallingConventions.Microsoft)]
    public delegate byte NoArgsRetByte();
    /// <summary>
    /// Wrapper for the C# precomputation hook function
    /// </summary>
    private IReverseWrapper<NoArgsRetByte>? _GetTurnAngleDiffReverse;

    const float M_2PI = (float)(2.0 * Math.PI);
    /// <summary>
    /// Compute angle difference since last call in *_angleDiff memory.
    /// </summary>
    /// <returns>1 if treadmill rotated since last time.</returns>
    private static byte _GetTurnAngleDiff()
    {
        KATTreadMillMemoryData data;
        GetWalkStatusWrapper!(out data, 0);
        float angle = data.bodyRotationRaw.GetAngle();
        if (Math.Abs(angle - _lastAngle) > 0.0001)
        {
            float diff = _lastAngle - angle;
            if (diff > Math.PI) diff -= M_2PI;
            else if (diff < -Math.PI) diff += M_2PI;
            unsafe { *_angleDiff = diff; }
            _lastAngle += diff;
            if (_lastAngle < 0) _lastAngle += M_2PI;
            else if (_lastAngle > M_2PI) _lastAngle -= M_2PI;
            return 1;
        }
        return 0;
    }

    /// <summary>
    /// Rotation handling code hook (GC protector)
    /// </summary>
    private IAsmHook? rotationHook;

    /// <summary>
    /// Hook installing code.
    /// </summary>
    private unsafe void SetupLookHook()
    {
        // Signature:
        //   $do_turn$:
        // (+ 0)  C6 87 [1C 33 00 00] 01       mov     byte ptr[rdi + 331Ch], 1; we turn
        // (+ 7)  F3 0F 11 [BD 58 13 00 00]    movss[rbp + 1330h + arg_18], xmm7; turn radians
        //   $check_addr$:
        // (+15)  38 9F [1C 33 00 00]          cmp[rdi + 331Ch], bl
        // (+21)  0F 84 [9B 23 00 00]          jz no_turn_needed [ no turn pressed handling ]
        //   $turn_handling$:
        // (+27)
        const string Signature = "C6 87 1C 33 00 00 01 F3 0F 11 ?? ?? ?? 00 00 38 9F 1C 33 00 00 0F 84 ?? ?? 00 00";
        
        // Initialize the scanner.
        var thisProcess = Process.GetCurrentProcess();
        byte* baseAddress = (byte*)thisProcess!.MainModule!.BaseAddress;
        int exeSize = thisProcess!.MainModule!.ModuleMemorySize;
        _modLoader.GetController<IScannerFactory>().TryGetTarget(out var scannerFactory);
        var scanner = scannerFactory!.CreateScanner(baseAddress, exeSize);

        // Search for a given pattern
        // Note: If created signature using SigMaker, replace ? with ??.
        var result = scanner.FindPattern(Signature);
        if (!result.Found)
        {
            _logger.WriteLine("Can't find signature");
            throw new Exception("Signature for getting LookHook not found.");
        }

        var do_turn_address = baseAddress + result.Offset;
        var turn_handling_address = baseAddress + result.Offset + 27;
        var no_turn_needed_address = *(int*)(do_turn_address + 23) + do_turn_address + 27;

        _logger.WriteLine($"Found addresses: do_turn: {(nuint)do_turn_address}, turn_handle: {(nuint)turn_handling_address}, no_turn: {(nuint)no_turn_needed_address}");

        // Search for an alignment gap nearby suitable for patching
        using var scanner2 = scannerFactory.CreateScanner((byte*)do_turn_address, exeSize-result.Offset);
        result = scanner2.FindPattern("CC CC CC CC CC CC CC CC");
        if (!result.Found)
        {
            _logger.WriteLine("Can't find a gap in the code.");
            throw new Exception("Can't find a gap in the code.");
        }
        if (result.Offset > 0x7FFFF000)
        {
            _logger.WriteLine("The gap is too far away,");
            throw new Exception("The gap is too far away.");
        }
        var hook_jmp_address = do_turn_address + result.Offset;
        _logger.WriteLine($"Hook jmp: {(nuint)hook_jmp_address}");

        string[] turnAdapterHook =
        {
            "use64",
             // Get the rotation delta
            $"{_hooks!.Utilities.GetAbsoluteCallMnemonics<NoArgsRetByte>(_GetTurnAngleDiff, out _GetTurnAngleDiffReverse)}",
            // Check is no rotation needed
            "cmp al, 0",
            // If no rotation needed, load skip address
            $"mov rax, qword {(nuint)no_turn_needed_address}",
            // Otherwise load saving address
            $"mov rcx, qword {(nuint)do_turn_address}",
            $"cmovne rax, rcx",
            // Load the turn diff into xmm7
            $"mov rcx, qword {(nuint)(_angleDiff)}",
            "movss xmm7, [rcx]",
            // return from hook to either do_turn or no_turn_needed
            "jmp rax"
        };

        try
        {
            rotationHook = _hooks!.CreateAsmHook(turnAdapterHook, (long)hook_jmp_address, AsmHookBehaviour.DoNotExecuteOriginal).Activate();
        }
        catch(Exception e)
        {
            _logger.WriteLine($"Jump hook: {String.Join("\n", turnAdapterHook)}");
            _logger.WriteLine($"Exception: {e.ToString()}");
            throw;
        }
        _logger.WriteLine($"Hook activated!");

        // Activate jmp to hook by chaning "jz no_turn_needed" into "jz hook_jmp_address"
        Memory.Instance.SafeWrite((nuint)(turn_handling_address - 4), BitConverter.GetBytes((int)(hook_jmp_address - turn_handling_address)));
        _logger.WriteLine($"Relative address written!");
    }

    /// <summary>
    /// Initialize the first rotation angle known to avoid jump-rotation.
    /// 
    /// Also dump debug data about treadmill connected for fun and debug.
    /// </summary>
    private unsafe void TouchKatWalk()
    {
        KATTreadMillMemoryData newdata;
        GetWalkStatusWrapper!(out newdata, 0);
        _logger.WriteLine($"Kat: '{newdata.deviceName}' connected: {newdata.connected}");
        _logger.WriteLine($"Rotation Q/w: {newdata.bodyRotationRaw.x} {newdata.bodyRotationRaw.y} {newdata.bodyRotationRaw.z} {newdata.bodyRotationRaw.w}");
        _logger.WriteLine($"Offset: {Marshal.OffsetOf<KATTreadMillMemoryData>("bodyRotationRaw")}");

        // throw new Exception("KAT is not connected");

        if (_GetTurnAngleDiff() != 0)
            _logger.WriteLine($"Turn platform angle changed by: {*_angleDiff}.");
        else
            _logger.WriteLine("Platform angle hasn't changed.");
    }
    #endregion

    public Mod(ModContext context)
    {
        _modLoader = context.ModLoader;
        _hooks = context.Hooks;
        _logger = context.Logger;
        _owner = context.Owner;
        _configuration = context.Configuration;
        _modConfig = context.ModConfig;

        if (LoadKatNative())
        {
            TouchKatWalk();
            _logger.WriteLine("Kat SDK loaded, injecting code");
            SetupLookHook();
        }
        // Comment out for release.
        else { throw new Exception("Can't load SDK, bail on start"); }
    }

    #region Native Imports
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern nuint LoadLibraryW([MarshalAs(UnmanagedType.LPWStr)] string lpFileName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    private static extern nuint GetProcAddress(nuint hModule, string procName);
    #endregion

    #region Standard Overrides
    public override void ConfigurationUpdated(Config configuration)
    {
        // Apply settings from configuration.
        // ... your code here.
        _configuration = configuration;
        _logger.WriteLine($"[{_modConfig.ModId}] Config Updated: Applying");
    }
    #endregion

    #region For Exports, Serialization etc.
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
    public Mod() { }
#pragma warning restore CS8618
    #endregion
}