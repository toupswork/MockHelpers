using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

using CommunityToolkit.Diagnostics;
using CommunityToolkit.HighPerformance.Helpers;


/// <summary>
/// For the provided type, create an expression to invoke the method. The values you provide are not used: they are only provided
/// to disambiguate which method from a set of overloads you wish to pic
/// </summary>
/// <typeparam name="T"></typeparam>
/// <param name="obj"></param>
public delegate void PickMethod<in T>(T obj);
/// <summary>
/// Create a function that takes in an instance of the type and modifies one or more fields
/// </summary>
/// <typeparam name="T"></typeparam>
/// <param name="index"></param>
/// <param name="obj"></param>
/// <returns></returns>
public delegate T MutateFn<T>(int index, T obj);
/// <summary>
/// Create an expression where you select a property on the specified object
/// </summary>
/// <typeparam name="T"></typeparam>
/// <typeparam name="TProperty"></typeparam>
/// <param name="obj"></param>
/// <returns></returns>
public delegate TProperty PickProperty<in T, out TProperty>(T obj);

public static class MockHelper
{
  [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "MemberwiseClone")]
  private static extern object ShallowCloneInstance(object o);

  /// <summary>
  /// Performs a shallow clone of the specified object.
  /// ⚠️ WARNING: Do not clone an empty instance created directly from <see cref="CreateEmptyObject{T}"/> without having
  /// at least one field initialized or the Code Coverage report will fail.
  /// </summary>
  /// <typeparam name="T">Type to clone</typeparam>
  /// <param name="obj">Instance of type to clone</param>
  /// <returns>A shallow clone of the provided instance</returns>
  public static T Clone<T>(T obj) where T : notnull => (T)ShallowCloneInstance(obj);

  /// <summary>
  /// Instantiates an instance of the type, bypassing the constructor. Helps when needing fake
  /// instances of types having deep constructor arguments
  /// </summary>
  /// <typeparam name="T"></typeparam>
  /// <returns></returns>
  public static T CreateEmptyObject<T>()
  {
    if (typeof(T) is { IsValueType: true }) return default(T)!;
    return (T)RuntimeHelpers.GetUninitializedObject(typeof(T));
  }
  /// <summary>
  /// Forcefully sets the value of a property, even if it has no public setter
  /// </summary>
  /// <typeparam name="T">Type having property</typeparam>
  /// <typeparam name="TP">Type of the property selected</typeparam>
  /// <param name="obj">Instance of the type</param>
  /// <param name="pickProperty">Create an expression that selects the property on the type</param>
  /// <param name="value">The value you wish to set the property to</param>
  /// <exception cref="ArgumentException">If expression is invalid</exception>
  public static void SetProperty<T, TP>(T obj, Expression<PickProperty<T, TP>> pickProperty, TP value)
  {
    if (pickProperty is not { Body: MemberExpression { Member: PropertyInfo pi } })
      throw new ArgumentException("Expression is not picking a property on the object", nameof(pickProperty));

    pi.SetValue(obj, value);
  }
  /// <summary>
  /// Instantiates one or more uninitialized instances of the type 
  /// </summary>
  /// <typeparam name="T"></typeparam>
  /// <param name="howMany">How many instances to create</param>
  /// <returns></returns>
  public static IEnumerable<T> MakeObjects<T>(int howMany) =>
    Enumerable.Range(0, howMany).Select(static _ => CreateEmptyObject<T>());
  /// <summary>
  /// Instantiates one or more uninitialized instances of the type, providing a mutator method to set one or more fields.
  /// This mutator method works best for record types or structs
  /// </summary>
  /// <typeparam name="T"></typeparam>
  /// <param name="howMany"></param>
  /// <param name="mutate"></param>
  /// <returns></returns>
  public static IEnumerable<T> MakeObjects<T>(int howMany, MutateFn<T> mutate) =>
    Enumerable.Repeat(mutate, howMany).Select(static (mutateFn, index) => mutateFn(index, CreateEmptyObject<T>()));
  /// <summary>
  /// Used to mock methods for dependencies that are otherwise un-mockable, such as static methods or sealed methods.
  /// Should be used as a last resort when other attempts to mock the dependency have failed
  /// </summary>
  /// <typeparam name="TSource">The type containing the method to redirect</typeparam>
  /// <typeparam name="TDestination">The type containing the method being redirected</typeparam>
  /// <param name="pickSourceMethod">Expression to pick the correct overload of the method to redirect</param>
  /// <param name="destMethodName">The name of the method on the destination type to redirect the source method to</param>
  /// <returns>A disposable object that when disposed will restore the method back to the original location</returns>
  /// <exception cref="ArgumentException">If the methods are incompatible</exception>
  public static IDisposable RedirectMethodUnsafe<TSource, TDestination>(Expression<PickMethod<TSource>> pickSourceMethod,
    string destMethodName) where TSource : class where TDestination : class
  {
    const BindingFlags allMethods = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static;
    Guard.IsNotNull(pickSourceMethod);
    Guard.IsNotNullOrEmpty(destMethodName);
    if (pickSourceMethod is not { Body: MethodCallExpression mce })
      throw new ArgumentException("Source expression is not a method invocation", nameof(pickSourceMethod));

    var argumentTypes = mce.Arguments.Select(x => x.Type);
    var destMethods = typeof(TDestination).GetMethods(allMethods)
                                          .Where(x => x.Name == destMethodName)
                                          .Where(x => x.GetParameters()
                                                       .Select(p => p.ParameterType)
                                                       .SequenceEqual(argumentTypes))
                                          .Where(x => x.ReturnType == mce.Method.ReturnType)
                                          .ToList();
    if (destMethods is not [{} destMethod])
      throw new ArgumentException("No matching method found in destination type", nameof(destMethodName));

    if (mce.Method is { IsAbstract: true } or { IsVirtual: true })
      return RedirectVirtualMethod(typeof(TSource), mce.Method, destMethod);

    return ReplaceFunction(mce.Method, destMethod);
  }
  /// <summary>
  /// Used to mock static. It patches the type method table to cause a method call to be redirected to the destination method you choose.
  /// Use the expressions to select the source and destination methods.
  /// </summary>
  /// <param name="pickSourceMethod"></param>
  /// <param name="pickDestinationMethod"></param>
  /// <returns></returns>
  /// <exception cref="ArgumentException"></exception>
  public static IDisposable RedirectStaticMethodUnsafe(Expression<Action> pickSourceMethod, Expression<Action> pickDestinationMethod)
  {
    if ((pickSourceMethod, pickDestinationMethod) is not (
    { Body: MethodCallExpression { Arguments: {} srcArgs, Method: {} srcMethod } },
    { Body: MethodCallExpression { Arguments: {} destArgs, Method: {} destMethod } }))
      throw new ArgumentException("Both expressions must be a method call");

    if (srcMethod.DeclaringType is { IsValueType: true } || destMethod.DeclaringType is { IsValueType: true })
      throw new ArgumentException("The source and destination methods must belong to a reference type");

    if (!srcArgs.Select(static x => x.Type).SequenceEqual(destArgs.Select(static x => x.Type)))
      throw new ArgumentException("The methods provided do not have the same arguments");

    if (srcMethod.ReturnType != destMethod.ReturnType)
      throw new ArgumentException("The methods provided do not return the same type");

    return ReplaceFunction(srcMethod, destMethod);
  }

  public static IDisposable RedirectMethodUnsafe<TSource, TDestination>(string sourceMethodName, string destMethodName)
    where TSource : class where TDestination : class
  {
    const BindingFlags allMethods = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static;
    Guard.IsNotNullOrEmpty(sourceMethodName);
    Guard.IsNotNullOrEmpty(destMethodName);
    
    var sourceMethodMatches = typeof(TSource).GetMethods(allMethods)
                                             .Where(x=>x.Name == sourceMethodName).ToList();

    if (sourceMethodMatches is not [{} match])
      throw new ArgumentException(
        sourceMethodMatches.Count is 0 ? 
        "Source has no matching method names" : "Source has more than one method matching the name provided", nameof(sourceMethodName));

    var argumentTypes = match.GetParameters().Select(p => p.ParameterType).ToList();
    var destMethods = typeof(TDestination).GetMethods(allMethods)
                                          .Where(x => x.Name == destMethodName)
                                          .Where(x => x.GetParameters()
                                                       .Select(p => p.ParameterType)
                                                       .SequenceEqual(argumentTypes))
                                          .Where(x => x.ReturnType == match.ReturnType)
                                          .ToList();
    if (destMethods is not [{ } dest])
      throw new ArgumentException("No matching method found in destination type", nameof(destMethodName));

    return ReplaceFunction(match, dest);
  }
  /// <summary>
  /// Used to mock methods for dependencies that are otherwise un-mockable, such as static methods or sealed methods.
  /// Should be used as a last resort when other attempts to mock the dependency have failed
  /// </summary>
  /// <typeparam name="TSource">The type containing the method to redirect</typeparam>
  /// <typeparam name="TDestination">The type containing the method being redirected</typeparam>
  /// <param name="pickSourceMethod">Expression to pick the correct overload of the method to redirect</param>
  /// <param name="pickDestinationMethod">Expression to pick the correct overload of the target method</param>
  /// <returns>A disposable object that when disposed will restore the method back to the original location</returns>
  /// <exception cref="ArgumentException">If the methods are incompatible</exception>
  public static IDisposable RedirectMethodUnsafe<TSource, TDestination>(Expression<Action<TSource>> pickSourceMethod,
    Expression<Action<TDestination>> pickDestinationMethod) where TSource : class where TDestination : class
  {

    if ((pickSourceMethod, pickDestinationMethod) is not (
      { Body: MethodCallExpression {Arguments: { } srcArgs, Method: { } srcMethod}}, 
      { Body: MethodCallExpression { Arguments: { } destArgs, Method: {} destMethod} }))
      throw new ArgumentException("Both expressions must be a method call");
    
    if (!srcArgs.Select(static x => x.Type).SequenceEqual(destArgs.Select(static x => x.Type)))
      throw new ArgumentException("The methods provided do not have the same arguments");

    if (srcMethod.ReturnType != destMethod.ReturnType)
      throw new ArgumentException("The methods provided do not return the same type");

    if (srcMethod is { IsAbstract: true } or { IsVirtual: true })
      return RedirectVirtualMethod(typeof(TSource), srcMethod, destMethod);

    return ReplaceFunction(srcMethod, destMethod);
  }
  /// <summary>
  /// Configures all public constructors to do nothing so that you can bypass any
  /// argument checks when instantiating the type
  /// </summary>
  /// <typeparam name="T">The type with constructors to Noop</typeparam>
  /// <returns>Disposable object that restores all constructors</returns>
  public static DisposeAggregate MakeNoOpCtor<T>()
  {
    const byte RET_OPCODE = 0xC3;
    var disposableAggregate = new DisposeAggregate();
    var ctors = typeof(T).GetConstructors(BindingFlags.Public).Select(x => x.MethodHandle);
    foreach (var ctor in ctors)
    {
      // Ensure the constructor is JIT-compiled
      RuntimeHelpers.PrepareMethod(ctor);

      // Get the JIT-compiled address of the constructor
      var ctorAddress = ctor.GetFunctionPointer();

      // Change memory protection to allow writing
      RuntimeInterop.UnlockPage(ctorAddress);

      disposableAggregate += new CtorRestorer(Marshal.ReadByte(ctorAddress), ctorAddress);
      // Write the "ret" opcode (0xC3) to the constructor's address
      Marshal.WriteByte(ctorAddress, RET_OPCODE);
    }

    return disposableAggregate;
  }


  public static IDisposable ReplaceFunction(MethodInfo source, MethodInfo destination)
  {

    GetJiTMethodAddress(source, out var sourceAddress);

    // allow writing to the destination to prevent a segmentation fault
    RuntimeInterop.UnlockPage(sourceAddress);

    // overwrite the function body of the source function with 
    GetJiTMethodAddress(destination, out var targetAddress);
    OverwriteSourcePreambleWithStub(sourceAddress, targetAddress, out var binaryBackup);
    
    return new MethodRestorer(sourceAddress, binaryBackup);
  }
  // Performs a long jump to another function
  private static void OverwriteSourcePreambleWithStub(IntPtr sourceAddress, IntPtr targetAddress, out byte[] binaryBackup)
  {
    const byte MOV = 0x48, MOV_RAX = 0xB8, JMP = 0xFF, JMP_RAX = 0xE0;
    const int preambleSize = 12;

    ReadFrom(binaryBackup = new byte[preambleSize], sourceAddress);

    Span<byte> preamble = stackalloc byte[preambleSize];
    
    preamble[0] = MOV; preamble[1] = MOV_RAX;
    BitConverter.GetBytes(targetAddress).AsSpan().CopyTo(preamble.Slice(2,8));
    preamble[10] = JMP; preamble[11] = JMP_RAX;

    CopyBytesToSource(ref preamble, sourceAddress);
  }

  static void ReadFrom(byte[] buffer, IntPtr address) => 
    Marshal.Copy(address, buffer, 0, buffer.Length);

  static void CopyBytesToSource(ref Span<byte> bytes, IntPtr destination) => 
    Marshal.Copy(bytes.ToArray(), 0, destination, bytes.Length);

  static void GetJiTMethodAddress(MethodInfo source, out IntPtr address)
  {
    var methodHandle = source.MethodHandle;
    RuntimeHelpers.PrepareMethod(methodHandle);
    address = Marshal.ReadIntPtr(methodHandle.Value, IntPtr.Size * 2);
  }

  static MethodInfo FindMatchingMethodInfo(Type type, MethodInfo mi) =>
    type.GetMethods()
        .Where(x => x.Name == mi.Name)
        .Where(x => x.ReturnType == mi.ReturnType)
        .Where(x => x.IsVirtual)
        .Where(x => x.GetParameters()
                     .Select(p => p.ParameterType)
                     .SequenceEqual(mi.GetParameters().Select(x => x.ParameterType)))
        .Where(x => x.IsGenericMethod == mi.IsGenericMethod &&
                    x.GetGenericArguments().Length == mi.GetGenericArguments().Length)
        .ToList() is [{ } first] ? first : null;

  private static IDisposable RedirectVirtualMethod(Type source, MethodInfo sourceMi, MethodInfo targetMethod)
  {
    const int methodTableFirstMethodOffset = 0x40;// 64 bytes offset

    var sourceMethod = FindMatchingMethodInfo(source, sourceMi);
    ArgumentNullException.ThrowIfNull(sourceMethod, "Could not find matching virtual method in source");
    // Prepare the method to ensure it's JIT-compiled
    RuntimeHelpers.PrepareMethod(sourceMethod.MethodHandle);

    // Get the slot index of the virtual method
    var (slotIndex, methodTable) = (RuntimeInterop.GetSlot(sourceMethod), source.TypeHandle.Value);
    var firstMethodIndex = Marshal.ReadIntPtr(methodTable + methodTableFirstMethodOffset);

    // Calculate the vtable slot address
    var vtableSlotPtr = firstMethodIndex + (IntPtr.Size * slotIndex);
    var sourceAddress = Marshal.ReadIntPtr(vtableSlotPtr);

    // Change memory protection to allow writing
    if (!RuntimeInterop.UnlockPage(sourceAddress))
      throw new InvalidOperationException("Failed to unlock page for virtual method table slot address");

    GetJiTMethodAddress(targetMethod, out var targetAddress);
    OverwriteSourcePreambleWithStub(sourceAddress, targetAddress, out var binaryBackup);
    return new MethodRestorer(sourceAddress, binaryBackup);
  }
}

public sealed class DisposeAggregate: IDisposable
{
  private readonly List<IDisposable> _disposables;
  public DisposeAggregate() => _disposables = [];

  public DisposeAggregate(List<IDisposable> disposables) => _disposables = disposables;
  public void Dispose() => _disposables.ForEach(x => x.Dispose());
  public static DisposeAggregate operator +(DisposeAggregate lhs, IDisposable rhs) => new([..lhs._disposables, rhs]);
}

file sealed class CtorRestorer(byte originalByte, IntPtr address): IDisposable
{
  public void Dispose() => Marshal.WriteByte(address,originalByte);
  public static DisposeAggregate operator +(CtorRestorer lhs, IDisposable rhs) => new([lhs, rhs]);
}
file sealed class MethodRestorer(IntPtr sourceAddress, byte[] backUpPreamble): IDisposable
{
  public void Dispose() => Marshal.Copy(backUpPreamble, 0, sourceAddress, backUpPreamble.Length);
  public static DisposeAggregate operator +(MethodRestorer lhs, IDisposable rhs) => new ([lhs, rhs]);
}

file static class RuntimeInterop
{
  private static Type _iRuntimeMethodInfoType = Type.GetType("System.IRuntimeMethodInfo, System.Private.CoreLib");

  private static readonly MethodInfo GetSlotMi = typeof(RuntimeMethodHandle)
                                                 .GetMethods(BindingFlags.NonPublic | BindingFlags.Static)
                                                 .Where(x => x.Name == "GetSlot")
                                                 .Where(x => x.GetParameters() is [{ } input] &&
                                                             input.ParameterType == _iRuntimeMethodInfoType)
                                                 .ToList() is [{ } mi] ? mi : null;
  public static int GetSlot(MethodInfo method)
  {
    GetSlotMi.Invoke(null, [method]).TryUnbox<int>(out var value);
    return value;
  }
  //private enum PageAttributes : uint
  //{
  //  PAGE_NOACCESS = 0x01,
  //  PAGE_READONLY = 0x02,
  //  PAGE_READWRITE = 0x04,
  //  PAGE_WRITECOPY = 0x08,
  //  PAGE_EXECUTE = 0x10,
  //  PAGE_EXECUTE_READ = 0x20,
  //  PAGE_EXECUTE_READWRITE = 0x40,
  //  PAGE_EXECUTE_WRITECOPY = 0x80,
  //  PAGE_GUARD = 0x100,
  //  PAGE_NOCACHE = 0x200,
  //  PAGE_WRITECOMBINE = 0x400
  //}
  [DllImport("kernel32.dll", EntryPoint = "VirtualProtect", SetLastError = true)]
  static extern bool VirtualProtectWindows(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

  [DllImport("libc", EntryPoint = "mprotect", SetLastError = true)]
  static extern int VirtualProtectLinux(IntPtr lpAddress, uint dwSize, uint flags);

  public static bool UnlockPage(IntPtr address)
  {
    if (OperatingSystem.IsWindows()) return UnlockPageWindows(address);
    return OperatingSystem.IsLinux() && UnlockPageLinux(address);
  }

  private static bool UnlockPageLinux(IntPtr address)
  {
    var newAddress = (address) & (long)(~0 << 12);
    var na = (IntPtr)newAddress;
    var length = ((long)address) + 6 - newAddress;
    // 1 for read, 2 for write, 4 for execute
    return VirtualProtectLinux(na, (uint)length, 1 | 2 | 4) > 0;
  }
  private static bool UnlockPageWindows(IntPtr address) =>
    VirtualProtectWindows(address, 6, 0x40, out _);


}