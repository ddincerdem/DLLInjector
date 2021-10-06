using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.IO;
using System.Runtime.ConstrainedExecution;
using System.Security;

namespace DLLFormApplication
{
    public partial class Form1 : Form
    {
        //static readonly IntPtr INTPTR_ZERO = (IntPtr)0;

        //[DllImport("kernel32.dll", SetLastError = true)] 
        //static extern IntPtr OpenProcess(uint dwDesiredAcces, int bInheritHandle, uint dwProcessId);

        //[DllImport("kernel32.dll", SetLastError = true)]
        //static extern int CloseHandle(IntPtr hObject);

        //[DllImport("kernel32.dll", SetLastError = true)]
        //static extern IntPtr GetProcAddress(IntPtr Hmodule , string lpProcName);

        //[DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        //public static extern IntPtr GetModuleHandle(string lpModuleName);

        //[DllImport("kernel32.dll", SetLastError = true)]
        //static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwsize, uint flAllocationType, uint flProtect);

        //[DllImport("kernel32.dll", SetLastError = true)]
        //static extern int WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddres, byte[] buffer, uint size, int lpNumberOfBytesWritten);

        //[DllImport("kernel32.dll", SetLastError = true)]
        //static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttribute, IntPtr dwStackSize, IntPtr lpStartAddres, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId );
        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess,bool bInheritHandle,int processId);
        public static IntPtr OpenProcess(Process proc, ProcessAccessFlags flags)
        {
            return OpenProcess(flags, false, proc.Id);
        }

        [Flags]
        public enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, AllocationType dwFreeType);

        [Flags]
        public enum MemoryProtection
        {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            GuardModifierflag = 0x100,
            NoCacheModifierflag = 0x200,
            WriteCombineModifierflag = 0x400
        }

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess,IntPtr lpAddress,IntPtr dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess,IntPtr lpBaseAddress,[MarshalAs(UnmanagedType.AsAny)] object lpBuffer,int dwSize,out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes,uint dwStackSize, IntPtr lpStartAddress,IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(IntPtr hObject);

        public Form1()
        {
            InitializeComponent();
        }

        //Olası sonuçlar listesi
        public enum DllInjectionResult
        {
            DllNotFound,
            ProcessNotFound,
            InjectionFailed,
            Succes
        }

        //Sonuçlarıyla birlikte DLL injectionu gerçekleştiren fonksiyon 
        public DllInjectionResult Inject(String sProcName, string sDLLPath)
        {
            if(!File.Exists(sDLLPath))
            {

                return DllInjectionResult.DllNotFound;

            }

            uint _procId = 0;

            Process[] _procs = Process.GetProcesses();

            for (int i = 0; i < _procs.Length; i++)
            {
                if (_procs[i].ProcessName == sProcName)
                {
                    _procId = (uint)_procs[i].Id;
                    break;
                }
            }

            if (_procId == 0)
            {
                return DllInjectionResult.ProcessNotFound;
            }

            if (!bInject(_procId, sDLLPath))
            {
                return DllInjectionResult.InjectionFailed;
            }

            return DllInjectionResult.Succes;
        }
        //Remote DLL 
        bool RemoteDLLInject(uint pToBeInject, string DllPath)
        {
            uint ProcId = pToBeInject;
            IntPtr Size = (IntPtr)DllPath.Length;

        
            // Step 1: Get the address of kernel32.dll's exported function: LoadLibraryA
            IntPtr Kernel32Handle = GetModuleHandle("Kernel32.dll");
            IntPtr LoadLibraryAAddress = GetProcAddress(Kernel32Handle, "LoadLibraryA");

            if (LoadLibraryAAddress== null)
            {
                MessageBox.Show("Could not get address kernel32.dll's LoadLibraryA");
                return false;
            }

            // Step 2: Get process handle from the target process
            try
            {
                Process localById = Process.GetProcessById((int)ProcId);
                string ProcName = localById.ProcessName;
            }
            catch (ArgumentException e)
            {
                return false;
            }
            
            IntPtr ProcHandle = OpenProcess(ProcessAccessFlags.All, false, (int)ProcId);
           
            if (ProcHandle == null)
            {
                MessageBox.Show("Could not obtain handle from 'OpenProcess");
                return false;
            }

            // Step 3: Allocate space to write the dll location
            IntPtr DllSpace = VirtualAllocEx(ProcHandle, IntPtr.Zero, Size, AllocationType.Reserve | AllocationType.Commit, MemoryProtection.ExecuteReadWrite);

            if (DllSpace == null)
            {
                CloseHandle(ProcHandle);
                MessageBox.Show(" Could not write DLL location using 'VirtualAllocEx'");
                return false;
            }

            // Step 4: Write the dll location to the space we allocated in step 3

            byte[] bytes = Encoding.ASCII.GetBytes(DllPath);
            bool DllWrite = WriteProcessMemory(ProcHandle, DllSpace, bytes, (int)bytes.Length, out var bytesread);

            if (!DllWrite)
            {
                CloseHandle(ProcHandle);
                MessageBox.Show("Could not write to process memory using 'WPM'");
                return false;
            }

            // Step 5: Load the dll using LoadLibraryA from step 1

            IntPtr RemoteThreadHandle;
            try
            {
                RemoteThreadHandle = CreateRemoteThread(ProcHandle, IntPtr.Zero, 0, LoadLibraryAAddress, DllSpace, 0, IntPtr.Zero);
            }
            catch (Exception)
            {
                RemoteThreadHandle = IntPtr.Zero;
                throw;
            }

            if (RemoteThreadHandle == IntPtr.Zero)
            {
                CloseHandle(ProcHandle);
                MessageBox.Show("Could not create a remote thread using 'CreateRemoteThread'");
                return false;
            }

            // Step 6: Close handles

            bool FreeDllSpace = VirtualFreeEx(ProcHandle, DllSpace, 0, AllocationType.Release);
            CloseHandle(RemoteThreadHandle);
            CloseHandle(ProcHandle);
            return true;
        }


        //Enjekte eden program 
        bool bInject(uint pToBeInject, string DllPath)
        {
            //unsigned olacak
            int ProcId = (int)pToBeInject;
            IntPtr Size = (IntPtr)DllPath.Length;

            if (!File.Exists(DllPath))
            {
                MessageBox.Show("Böyle bir DLL yok!");
                return false;
            }
            try
            {
                Process localById = Process.GetProcessById(ProcId);
                string ProcName = localById.ProcessName;
            }
            catch (ArgumentException e)
            {
                MessageBox.Show("7 Numaralı hata");
                return false;
            }

            // OpenProcess ile ProcID ve gerekli izinler ile kullanılacak process seçilir 

            IntPtr ProcHandle = OpenProcess( ProcessAccessFlags.All,false,ProcId);

            if (ProcHandle == null)
            {
                MessageBox.Show("1 Numaralı hata");
                return false;
            }

            // Victim Process'in içerisinin sanal adresinde yer ayıran fonksiyon

            IntPtr DllSpace = VirtualAllocEx(ProcHandle,IntPtr.Zero,Size,AllocationType.Reserve | AllocationType.Commit,MemoryProtection.ExecuteReadWrite);

            if (DllSpace == null)
            {
                MessageBox.Show("2 Numaralı hata");
                return false;
            }
           
            //Ele alınan process'in ayrılan bellek alanına enjekte edilecel DLL dosyasının yolunu yazmak için WriteProcessMemory() kullanılır.

            byte[] bytes = Encoding.ASCII.GetBytes(DllPath);
            bool DllWrite = WriteProcessMemory(ProcHandle,DllSpace,bytes, (int)bytes.Length,out var bytesread);

            if (!DllWrite)
            {
                MessageBox.Show("3 Numaralı hata");
                return false;
            }

            //GetModuleHandle fonksiyonu ile ele alıncak DLL kütüphanesi belirlenir ve içeride çalıştırılacak LoadLibraryA() fonksiyonunun adresi GetProcAdress ile alınır.

            IntPtr Kernel32Handle = GetModuleHandle("Kernel32.dll");
            IntPtr LoadLibraryAAddress = GetProcAddress(Kernel32Handle, "LoadLibraryA");

            if (LoadLibraryAAddress == null)
            {
                MessageBox.Show("4 Numaralı hata");
                return false;
            }

            //CreateRemoteThread() fonksiyonu bir processin sanal bellek alanında thread oluşturur. Bu fonksiyon sayesinde LoadLibraryA() fonksiyonu processin ayrılan 
            //kısmında bir thread olarak çalıştırılır. Böylece DLL enjekte edilmiş olur.
            //!!!!!!!!!!!!!!!!!!!

            IntPtr RemoteThreadHandle;
            try
            {
              RemoteThreadHandle = CreateRemoteThread(ProcHandle, IntPtr.Zero, 0, LoadLibraryAAddress, DllSpace, 0, IntPtr.Zero);
            }
            catch (Exception)
            {
                RemoteThreadHandle = IntPtr.Zero;
                throw;
            }

            if (RemoteThreadHandle == null)
            {
                MessageBox.Show("5 Numaralı hata");
                return false;
            }

            // Deallocate memory assigned to DLL
            bool FreeDllSpace = VirtualFreeEx(ProcHandle,DllSpace,0,AllocationType.Release);

            if (FreeDllSpace == false)
            {
                MessageBox.Show("6 Numaralı hata");
                return false;
            }

            // Close remote thread handle
            CloseHandle(RemoteThreadHandle);

            // Close target process handle
            CloseHandle(ProcHandle);
            return true;
        }

        //Injection başamadan önceki ara katman 
        private void InjectMode()
        {
                Process[] ProcessCollection = Process.GetProcesses();
                
                foreach (Process p in ProcessCollection)
                {
                    if (p.ProcessName == PNameT.Text.ToString())
                    {
                        Inject(PNameT.Text, DllPathT.Text);
                        break;
                    }
                }
           
        }

        //ListBoxtan seçim yapıp TextBox'a yazdırmaya yarıyor
        private void listBox1_DoubleClick(object sender, EventArgs e)
        {
            if (listBox1.Items.Count != 0 )
            {
                PNameT.Text = listBox1.SelectedItem.ToString();
            }
        }
       
        //Injectionu başlatıyor 
        private void button3_Click(object sender, EventArgs e)
        {
            InjectMode();
        }
        
        //DLL'leri Listeliyor
        private void button2_Click(object sender, EventArgs e)
        {
            listBox1.Items.Clear();
            Process[] processes = Process.GetProcesses();
            for (int i = 0; i < processes.Length; i++)
            {
                Process p = processes[i];
                listBox1.Items.Add(p.ProcessName);
            }
        }

        //DLL seçtiren Open Dialogu açıyor 
        private void button1_Click(object sender, EventArgs e)
        {
            openFileDialog1 = new OpenFileDialog();
            if (openFileDialog1.ShowDialog() == DialogResult.OK)
            {
                DllPathT.Text = openFileDialog1.FileName;
            }
        }
    }
}
