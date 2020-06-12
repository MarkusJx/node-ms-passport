using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace GacInstaller
{
    class GacInstaller
    {
        // Check if assembly is in gac. Source: https://stackoverflow.com/a/19459379
        [DllImport("fusion.dll")]
        private static extern IntPtr CreateAssemblyCache(
        out IAssemblyCache ppAsmCache,
        int reserved);

        [ComImport]
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        [Guid("e707dcde-d1cd-11d2-bab9-00c04f8eceae")]
        private interface IAssemblyCache
        {
            int Dummy1();

            [PreserveSig()]
            IntPtr QueryAssemblyInfo(
                int flags,
                [MarshalAs(UnmanagedType.LPWStr)] string assemblyName,
                ref AssemblyInfo assemblyInfo);

            int Dummy2();
            int Dummy3();
            int Dummy4();
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct AssemblyInfo
        {
            public int cbAssemblyInfo;
            public int assemblyFlags;
            public long assemblySizeInKB;

            [MarshalAs(UnmanagedType.LPWStr)]
            public string currentAssemblyPath;

            public int cchBuf;
        }

        public static bool IsAssemblyInGAC(string assemblyName)
        {
            var assembyInfo = new AssemblyInfo { cchBuf = 512 };
            assembyInfo.currentAssemblyPath = new string('\0', assembyInfo.cchBuf);

            IAssemblyCache assemblyCache;

            var hr = CreateAssemblyCache(out assemblyCache, 0);

            if (hr == IntPtr.Zero)
            {
                hr = assemblyCache.QueryAssemblyInfo(1, assemblyName, ref assembyInfo);

                if (hr != IntPtr.Zero)
                {
                    return false;
                }

                return true;
            }

            Marshal.ThrowExceptionForHR(hr.ToInt32());
            return false;
        }

        public static string AssemblyDirectory
        {
            get
            {
                string codeBase = Assembly.GetExecutingAssembly().CodeBase;
                UriBuilder uri = new UriBuilder(codeBase);
                string path = Uri.UnescapeDataString(uri.Path);
                return Path.GetDirectoryName(path);
            }
        }

        static int Main(string[] args)
        {
            if (args.Length >= 2)
            {
                if (args[0] == "install")
                {
                    new System.EnterpriseServices.Internal.Publish().GacInstall(System.IO.Path.GetFullPath(args[1]));
                    if (!IsAssemblyInGAC(args[1].Replace(".dll", "")))
                    {
                        Console.WriteLine("Assembly installation failed");
                        return 2;
                    }
                    else
                    {
                        Console.WriteLine("Assembly successfully installed");
                        return 0;
                    }
                }
                else if (args[0] == "remove")
                {
                    new System.EnterpriseServices.Internal.Publish().GacRemove(System.IO.Path.GetFullPath(args[1]));

                    if (IsAssemblyInGAC(args[1]))
                    {
                        Console.WriteLine("Assembly removal failed");
                        return 2;
                    }
                    else
                    {
                        Console.WriteLine("Assembly successfully removed");
                        return 0;
                    }
                }
                else if (args[0] == "check")
                {
                    Console.WriteLine("Assembly in GAC: ");
                    Console.WriteLine(IsAssemblyInGAC(args[1]));
                    return 0;
                }
                else
                {
                    Console.WriteLine("Unknown command");
                    return 1;
                }
            }
            else
            {
                Console.WriteLine("2 Arguments required");
                return -1;
            }
        }
    }
}
