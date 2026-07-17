using System.Text;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

namespace HydraDeobfuscator;

internal static class Program
{
    private const string KeyResourceName = "HailHydra";

    private static int Main(string[] args)
    {
        if (args.Length is < 1 or > 2 || args[0] is "-h" or "--help")
        {
            PrintUsage();
            return args.Length == 0 ? 1 : 0;
        }

        var input = Path.GetFullPath(args[0]);
        var output = args.Length == 2
            ? Path.GetFullPath(args[1])
            : Path.Combine(Path.GetDirectoryName(input)!,
                Path.GetFileNameWithoutExtension(input) + ".hydra-deob" + Path.GetExtension(input));

        if (!File.Exists(input))
        {
            Console.Error.WriteLine($"Input does not exist: {input}");
            return 2;
        }

        try
        {
            var image = File.ReadAllBytes(input);
            var repairedSections = RepairSwappedSectionAddresses(image);
            using var module = ModuleDefMD.Load(image, new ModuleCreationOptions
            {
                TryToLoadPdbFromDisk = false
            });

            var key = ExtractHydraKey(module);
            Console.WriteLine(key == null
                ? "[!] HailHydra resource was not found; trying shift-only and cleanup passes."
                : $"[+] Extracted {key.Length}-byte HailHydra key.");
            if (repairedSections)
                Console.WriteLine("[+] Repaired swapped PE section virtual addresses in memory.");

            var stringCount = DecryptStrings(module, key);
            var hiddenStringCount = RecoverStringsHider(module);
            var replacementCount = RemoveReplaceObfuscation(module);
            var predicateCount = RemoveSimpleOpaquePredicates(module);
            var junkCount = RemoveJunkInstructions(module);
            var detections = DetectUnsupportedProtections(module);
            RemoveHydraAttributes(module);

            var options = new ModuleWriterOptions(module)
            {
                Logger = DummyLogger.NoThrowInstance
            };
            options.MetadataOptions.Flags |= MetadataFlags.PreserveAll;
            module.Write(output, options);

            Console.WriteLine($"[+] Decrypted {stringCount} protected string call sites.");
            Console.WriteLine($"[+] Recovered {hiddenStringCount} StringsHider fields.");
            Console.WriteLine($"[+] Removed {replacementCount} homoglyph/Replace string chains.");
            Console.WriteLine($"[+] Neutralized {predicateCount} constant opaque branches.");
            Console.WriteLine($"[+] Removed {junkCount} harmless junk instructions/calls.");
            foreach (var detection in detections)
                Console.WriteLine($"[!] Detected optional protection requiring a specialized runtime pass: {detection}");
            Console.WriteLine($"[+] Wrote: {output}");
            return 0;
        }
        catch (BadImageFormatException ex)
        {
            Console.Error.WriteLine("The assembly has damaged PE section mappings. Run the included repair command first:");
            Console.Error.WriteLine($"  HydraDeobfuscator repair \"{input}\" \"{output}\"");
            Console.Error.WriteLine(ex.Message);
            return 3;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Deobfuscation failed: {ex.Message}");
            return 4;
        }
    }

    private sealed record Section(int HeaderOffset, uint VirtualSize, uint VirtualAddress,
                                  uint RawSize, uint RawOffset);

    private static bool RepairSwappedSectionAddresses(byte[] image)
    {
        using var stream = new MemoryStream(image, writable: false);
        using var pe = new PEReader(stream, PEStreamOptions.LeaveOpen);
        if (!pe.HasMetadata)
            return false;
        var reader = pe.GetMetadataReader();
        var methodRvas = reader.MethodDefinitions
            .Select(h => reader.GetMethodDefinition(h).RelativeVirtualAddress)
            .Where(rva => rva != 0)
            .ToArray();

        var peOffset = BitConverter.ToInt32(image, 0x3C);
        var sectionCount = BitConverter.ToUInt16(image, peOffset + 6);
        var optionalSize = BitConverter.ToUInt16(image, peOffset + 20);
        var table = peOffset + 24 + optionalSize;
        var sections = new List<Section>();
        for (var i = 0; i < sectionCount; i++)
        {
            var off = table + i * 40;
            sections.Add(new Section(off,
                BitConverter.ToUInt32(image, off + 8),
                BitConverter.ToUInt32(image, off + 12),
                BitConverter.ToUInt32(image, off + 16),
                BitConverter.ToUInt32(image, off + 20)));
        }

        var originalScore = ScoreMethodBodies(image, sections, methodRvas);
        var bestScore = originalScore;
        (int A, int B)? bestSwap = null;
        for (var a = 0; a < sections.Count; a++)
        for (var b = a + 1; b < sections.Count; b++)
        {
            var candidate = sections.ToArray();
            candidate[a] = candidate[a] with { VirtualAddress = sections[b].VirtualAddress };
            candidate[b] = candidate[b] with { VirtualAddress = sections[a].VirtualAddress };
            var score = ScoreMethodBodies(image, candidate, methodRvas);
            if (score > bestScore)
            {
                bestScore = score;
                bestSwap = (a, b);
            }
        }

        if (bestSwap == null || bestScore < originalScore + Math.Max(5, methodRvas.Length / 10))
            return false;

        var (first, second) = bestSwap.Value;
        WriteUInt32(image, sections[first].HeaderOffset + 12, sections[second].VirtualAddress);
        WriteUInt32(image, sections[second].HeaderOffset + 12, sections[first].VirtualAddress);
        return true;
    }

    private static int ScoreMethodBodies(byte[] image, IReadOnlyList<Section> sections, IEnumerable<int> methodRvas)
    {
        var score = 0;
        foreach (var signedRva in methodRvas)
        {
            var rva = (uint)signedRva;
            var section = sections.FirstOrDefault(s =>
                rva >= s.VirtualAddress && rva < s.VirtualAddress + Math.Max(s.VirtualSize, s.RawSize));
            if (section == null)
                continue;
            var offset = (long)section.RawOffset + rva - section.VirtualAddress;
            if (offset < 0 || offset >= image.Length)
                continue;
            var first = image[offset];
            if ((first & 3) == 2)
            {
                var size = first >> 2;
                if (offset + 1 + size <= image.Length) score++;
            }
            else if ((first & 3) == 3 && offset + 12 <= image.Length)
            {
                var flags = BitConverter.ToUInt16(image, (int)offset);
                var headerSize = (flags >> 12) * 4;
                var codeSize = BitConverter.ToUInt32(image, (int)offset + 4);
                if (headerSize >= 12 && headerSize <= 64 && offset + headerSize + codeSize <= image.Length)
                    score++;
            }
        }
        return score;
    }

    private static void WriteUInt32(byte[] data, int offset, uint value) =>
        BitConverter.GetBytes(value).CopyTo(data, offset);

    private static byte[]? ExtractHydraKey(ModuleDefMD module)
    {
        var resource = module.Resources.OfType<EmbeddedResource>()
            .FirstOrDefault(r => r.Name == KeyResourceName);
        if (resource == null)
            return null;

        var stored = resource.CreateReader().ToArray();
        if (stored.Length == 0)
            return null;

        var key = new byte[stored.Length];
        for (var i = 0; i < stored.Length; i++)
            key[i] = (byte)(stored[i] ^ 0xAA);
        return key;
    }

    private static int DecryptStrings(ModuleDef module, byte[]? xorKey)
    {
        var count = 0;
        foreach (var method in module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody))
        {
            var instructions = method.Body.Instructions;
            method.Body.SimplifyMacros(method.Parameters);

            for (var i = 0; i < instructions.Count; i++)
            {
                if (xorKey != null && i + 7 < instructions.Count &&
                    instructions[i].OpCode == OpCodes.Ldstr &&
                    instructions.Skip(i + 1).Take(5).All(x => x.IsLdcI4()) &&
                    IsStringShiftDecoderCall(instructions[i + 6]) &&
                    IsStringXorDecoderCall(instructions[i + 7]))
                {
                    var encrypted = (string)instructions[i].Operand;
                    var shiftKey = instructions[i + 2].GetLdcI4Value();
                    if (TryDecryptFull(encrypted, shiftKey, xorKey, out var clear))
                    {
                        instructions[i].Operand = clear;
                        Nop(instructions, i + 1, 7);
                        count++;
                        continue;
                    }
                }

                if (i + 6 < instructions.Count &&
                    instructions[i].OpCode == OpCodes.Ldstr &&
                    instructions.Skip(i + 1).Take(5).All(x => x.IsLdcI4()) &&
                    IsStringShiftDecoderCall(instructions[i + 6]))
                {
                    var encrypted = (string)instructions[i].Operand;
                    var shiftKey = instructions[i + 2].GetLdcI4Value();
                    instructions[i].Operand = ShiftDecrypt(encrypted, shiftKey);
                    Nop(instructions, i + 1, 6);
                    count++;
                    continue;
                }

                if (xorKey != null && i + 1 < instructions.Count &&
                    instructions[i].OpCode == OpCodes.Ldstr &&
                    IsStringXorDecoderCall(instructions[i + 1]) &&
                    TryXorBase64((string)instructions[i].Operand, xorKey, out var xorClear))
                {
                    instructions[i].Operand = xorClear;
                    instructions[i + 1].OpCode = OpCodes.Nop;
                    instructions[i + 1].Operand = null;
                    count++;
                }
            }

            method.Body.OptimizeBranches();
            method.Body.OptimizeMacros();
        }
        return count;
    }

    private static bool IsStringShiftDecoderCall(Instruction instruction)
    {
        if (instruction.OpCode != OpCodes.Call || instruction.Operand is not IMethod method)
            return false;
        var sig = method.MethodSig;
        return sig != null && sig.Params.Count == 6 &&
               sig.RetType.ElementType == ElementType.String &&
               sig.Params[0].ElementType == ElementType.String &&
               sig.Params.Skip(1).All(p => p.ElementType == ElementType.I4);
    }

    private static bool IsStringXorDecoderCall(Instruction instruction)
    {
        if (instruction.OpCode != OpCodes.Call || instruction.Operand is not IMethod method)
            return false;
        var sig = method.MethodSig;
        return sig != null && sig.Params.Count == 1 &&
               sig.RetType.ElementType == ElementType.String &&
               sig.Params[0].ElementType == ElementType.String;
    }

    private static bool TryDecryptFull(string encrypted, int shiftKey, byte[] xorKey, out string clear)
    {
        var stageOne = ShiftDecrypt(encrypted, shiftKey);
        return TryXorBase64(stageOne, xorKey, out clear);
    }

    private static string ShiftDecrypt(string encrypted, int key)
    {
        var chars = encrypted.ToCharArray();
        for (var i = 0; i < chars.Length; i++)
            chars[i] = unchecked((char)(chars[i] - key));
        return new string(chars);
    }

    private static bool TryXorBase64(string encrypted, byte[] key, out string clear)
    {
        clear = "";
        try
        {
            var data = Convert.FromBase64String(encrypted);
            for (var i = 0; i < data.Length; i++)
                data[i] ^= key[i % key.Length];
            clear = new UTF8Encoding(false, true).GetString(data);
            return true;
        }
        catch (FormatException) { return false; }
        catch (DecoderFallbackException) { return false; }
    }

    private static int RemoveSimpleOpaquePredicates(ModuleDef module)
    {
        var count = 0;
        foreach (var method in module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody))
        {
            var ins = method.Body.Instructions;
            for (var i = 0; i + 1 < ins.Count; i++)
            {
                if (!ins[i].IsLdcI4())
                    continue;
                var value = ins[i].GetLdcI4Value();
                var branch = ins[i + 1];
                var taken = branch.OpCode is { } op &&
                    ((op == OpCodes.Brtrue || op == OpCodes.Brtrue_S) ? value != 0 :
                     (op == OpCodes.Brfalse || op == OpCodes.Brfalse_S) && value == 0);
                var isConditional = branch.OpCode == OpCodes.Brtrue || branch.OpCode == OpCodes.Brtrue_S ||
                                    branch.OpCode == OpCodes.Brfalse || branch.OpCode == OpCodes.Brfalse_S;
                if (!isConditional)
                    continue;

                ins[i].OpCode = OpCodes.Nop;
                ins[i].Operand = null;
                if (taken)
                    branch.OpCode = OpCodes.Br;
                else
                {
                    branch.OpCode = OpCodes.Nop;
                    branch.Operand = null;
                }
                count++;
            }
            method.Body.OptimizeBranches();
        }
        return count;
    }

    private static int RecoverStringsHider(ModuleDef module)
    {
        var recovered = new Dictionary<IField, string>();
        foreach (var type in module.GetTypes())
        {
            var cctor = type.FindStaticConstructor();
            if (cctor?.HasBody != true)
                continue;
            var ins = cctor.Body.Instructions;
            for (var i = 0; i < ins.Count; i++)
            {
                if (!IsEncodingUtf8Getter(ins[i]))
                    continue;
                var cursor = i + 1;
                if (cursor >= ins.Count || !ins[cursor].IsLdcI4()) continue;
                var length = ins[cursor++].GetLdcI4Value();
                if (length < 0 || length > 16 * 1024 * 1024 || cursor >= ins.Count ||
                    ins[cursor].OpCode != OpCodes.Newarr) continue;
                cursor++;
                var bytes = new byte[length];
                var seen = new bool[length];
                while (cursor + 3 < ins.Count && ins[cursor].OpCode == OpCodes.Dup &&
                       ins[cursor + 1].IsLdcI4() && ins[cursor + 2].IsLdcI4() &&
                       ins[cursor + 3].OpCode == OpCodes.Stelem_I1)
                {
                    var index = ins[cursor + 1].GetLdcI4Value();
                    if ((uint)index < (uint)length)
                    {
                        bytes[index] = unchecked((byte)ins[cursor + 2].GetLdcI4Value());
                        seen[index] = true;
                    }
                    cursor += 4;
                }
                if (cursor + 1 >= ins.Count || !IsEncodingGetString(ins[cursor]) ||
                    ins[cursor + 1].OpCode != OpCodes.Stsfld ||
                    ins[cursor + 1].Operand is not IField field || seen.Any(x => !x))
                    continue;
                try
                {
                    recovered[field] = new UTF8Encoding(false, true).GetString(bytes);
                    Nop(ins, i, cursor + 2 - i);
                    i = cursor + 1;
                }
                catch (DecoderFallbackException) { }
            }
        }

        var replacements = 0;
        foreach (var method in module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody))
        foreach (var instruction in method.Body.Instructions)
            if (instruction.OpCode == OpCodes.Ldsfld && instruction.Operand is IField field &&
                recovered.TryGetValue(field, out var value))
            {
                instruction.OpCode = OpCodes.Ldstr;
                instruction.Operand = value;
                replacements++;
            }
        return replacements;
    }

    private static int RemoveReplaceObfuscation(ModuleDef module)
    {
        var count = 0;
        const string removable = "аеіос\u2029";
        foreach (var method in module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody))
        {
            var ins = method.Body.Instructions;
            for (var i = 0; i < ins.Count; i++)
            {
                if (ins[i].OpCode != OpCodes.Ldstr || ins[i].Operand is not string value)
                    continue;
                var cursor = i + 1;
                var chainEnd = cursor;
                var calls = 0;
                while (cursor + 2 < ins.Count && ins[cursor].OpCode == OpCodes.Ldstr &&
                       ins[cursor + 1].OpCode == OpCodes.Ldstr &&
                       (string)ins[cursor + 1].Operand == "" && IsStringReplace(ins[cursor + 2]))
                {
                    chainEnd = cursor + 3;
                    calls++;
                    cursor += 3;
                }
                if (calls == 0)
                    continue;
                ins[i].Operand = new string(value.Where(c => !removable.Contains(c)).ToArray());
                Nop(ins, i + 1, chainEnd - i - 1);
                count++;
            }
        }
        return count;
    }

    private static int RemoveJunkInstructions(ModuleDef module)
    {
        var count = 0;
        foreach (var method in module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody))
        {
            var ins = method.Body.Instructions;
            for (var i = 0; i + 1 < ins.Count; i++)
            {
                if (ins[i].IsLdcI4() && ins[i].GetLdcI4Value() == 1 &&
                    ins[i + 1].OpCode == OpCodes.Call && ins[i + 1].Operand is IMethod called &&
                    called.Name == "Assert" && called.DeclaringType?.FullName == "System.Diagnostics.Debug")
                {
                    Nop(ins, i, 2);
                    count += 2;
                    i++;
                    continue;
                }
                if (ins[i].IsLdcI4() && ins[i].GetLdcI4Value() == 0 &&
                    (ins[i + 1].OpCode == OpCodes.Add || ins[i + 1].OpCode == OpCodes.Sub ||
                     ins[i + 1].OpCode == OpCodes.Shl || ins[i + 1].OpCode == OpCodes.Shr))
                {
                    Nop(ins, i, 2);
                    count += 2;
                    i++;
                }
            }
            method.Body.OptimizeBranches();
            method.Body.OptimizeMacros();
        }
        return count;
    }

    private static IReadOnlyList<string> DetectUnsupportedProtections(ModuleDef module)
    {
        var hits = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        var names = module.GetTypes().Select(t => t.FullName)
            .Concat(module.Resources.Select(r => r.Name.String));
        foreach (var name in names)
        {
            if (name.Contains("EXGuard", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("VMRuntime", StringComparison.OrdinalIgnoreCase)) hits.Add("EXGuard/VM virtualization");
            if (name.Contains("JITRuntime", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("JIT", StringComparison.OrdinalIgnoreCase)) hits.Add("JIT method encryption");
            if (name.Contains("Packer", StringComparison.OrdinalIgnoreCase)) hits.Add("assembly packer");
            if (name.Contains("AntiDump", StringComparison.OrdinalIgnoreCase)) hits.Add("anti-dump runtime");
        }
        foreach (var method in module.GetTypes().SelectMany(t => t.Methods))
            if (method.NativeBody != null)
                hits.Add("native/unmanaged method bodies or strings");
        return hits.ToArray();
    }

    private static bool IsEncodingUtf8Getter(Instruction instruction) =>
        instruction.OpCode == OpCodes.Call && instruction.Operand is IMethod m &&
        m.Name == "get_UTF8" && m.DeclaringType?.FullName == "System.Text.Encoding";

    private static bool IsEncodingGetString(Instruction instruction) =>
        (instruction.OpCode == OpCodes.Call || instruction.OpCode == OpCodes.Callvirt) &&
        instruction.Operand is IMethod m && m.Name == "GetString" &&
        m.DeclaringType?.FullName == "System.Text.Encoding";

    private static bool IsStringReplace(Instruction instruction) =>
        (instruction.OpCode == OpCodes.Call || instruction.OpCode == OpCodes.Callvirt) &&
        instruction.Operand is IMethod m && m.Name == "Replace" &&
        m.DeclaringType?.FullName == "System.String";

    private static void RemoveHydraAttributes(ModuleDef module)
    {
        foreach (var owner in module.GetTypes().Cast<IHasCustomAttribute>().Append(module))
        {
            for (var i = owner.CustomAttributes.Count - 1; i >= 0; i--)
                if (owner.CustomAttributes[i].AttributeType.FullName.Contains("Hydra", StringComparison.OrdinalIgnoreCase))
                    owner.CustomAttributes.RemoveAt(i);
        }
    }

    private static void Nop(IList<Instruction> instructions, int start, int length)
    {
        for (var i = start; i < start + length; i++)
        {
            instructions[i].OpCode = OpCodes.Nop;
            instructions[i].Operand = null;
        }
    }

    private static void PrintUsage()
    {
        Console.WriteLine("HydraDeobfuscator <input.dll|exe> [output.dll|exe]");
        Console.WriteLine();
        Console.WriteLine("Statically removes upstream DestroyerDarkNess/Hydra string encryption");
        Console.WriteLine("and simple opaque branches. The input assembly is never executed.");
    }
}
