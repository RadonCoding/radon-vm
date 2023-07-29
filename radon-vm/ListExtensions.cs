using System.Reflection.Emit;
using System.Reflection;

namespace VeProt_Native {
    public static class ListExtensions {
        private static class ArrayAccessor<T> {
            public static Func<List<T>, T[]> Getter;

            static ArrayAccessor() {
                var dm = new DynamicMethod("get", MethodAttributes.Static | MethodAttributes.Public, CallingConventions.Standard, typeof(T[]), new Type[] { typeof(List<T>) }, typeof(ArrayAccessor<T>), true);
                FieldInfo? items = typeof(List<T>).GetField("_items", BindingFlags.NonPublic | BindingFlags.Instance);

                // Will never happen
                if (items == null) throw new Exception();

                var il = dm.GetILGenerator();
                il.Emit(OpCodes.Ldarg_0);
                il.Emit(OpCodes.Ldfld, items);
                il.Emit(OpCodes.Ret);
                Getter = (Func<List<T>, T[]>)dm.CreateDelegate(typeof(Func<List<T>, T[]>));
            }
        }

        public static T[] GetInternalArray<T>(this List<T> list) {
            return ArrayAccessor<T>.Getter(list);
        }
    }
}
