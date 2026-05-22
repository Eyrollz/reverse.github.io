---
title: Partie 26 - Seccomp - fonctionnement (1/2)
date: 2026-04-13 10:00:00
categories: [Pwn, Introduction au pwn]
tags: [x86, pwn, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# Seccomp : fonctionnement (1/2)

Avoir la possibilité d'exécuter un *shellcode* dans un programme exploité permet d'avoir accès à un très grand nombre d'actions possibles :

- ouvrir un **terminal** ;
- gérer des **connexions réseau** ;
- ouvrir, lire et écrire des **fichiers** ;
- et bien plus encore.

Une idée qui peut rapidement venir à l’esprit est la suivante : mon programme "Hello world" ne fait qu’afficher une chaîne de caractères. Pourquoi ne pas restreindre les appels système autorisés à `read` et `write` uniquement ?

Eh bien c'est justement ce que permet de faire **seccomp** !

## Qu'est-ce que seccomp ?

**seccomp** signifie **SECCure COMPuting** (informatique sécurisée 🥖). Il s'agit d'un mécanisme disponible sous Linux qui permet de **filtrer les appels système** accessibles depuis une application.

Il y a principalement **trois manières** de le mettre en place :

- **bloquer** certains appels système (**liste noire**) ;
- **autoriser** certains appels système (**liste blanche**) ;
- **filtrer** certains appels système en fonction de leurs **arguments**.

**seccomp** est une fonctionnalité assez [ancienne](https://fr.wikipedia.org/wiki/Seccomp) mais qui reste utilisée dans des applications qui nécessitent une sécurité accrue :

- [Chromium](https://chromium.googlesource.com/chromium/src/+/0e94f26e8/docs/linux_sandboxing.md) ;
- [Docker](https://docs.docker.com/engine/security/seccomp/);
- et [plein d'autres](https://fr.wikipedia.org/wiki/Seccomp#Logiciels_utilisant_seccomp_et_seccomp-bpf).

> Contrairement à ce que l’on pourrait penser, **seccomp** n’est **pas un mécanisme de cloisonnement** (*sandboxing*) à part entière.
> 
> Il se limite à **restreindre les appels système** qu’un programme est autorisé à invoquer, en appliquant un filtrage au niveau du noyau, sans fournir à lui seul **d’isolation complète** de l’environnement d’exécution.
{: .prompt-warning }

## Comment cela fonctionne ?

### 🔒 Le mode strict (`SECCOMP_SET_MODE_STRICT`)

Initialement **seccomp** limitait les appels système que peut exécuter un programme aux **quatre suivants** :

- `read` ;
- `write`;
- `exit` ;
- `sigreturn`.

Si le programme exécute un autre appel système que ceux-là, le signal `SIGKILL` sera envoyé au programme.

> Ah ouais c'est la hess 😆 !
{: .prompt-tip }

Eh oui ... Le programme ouvre un fichier ? ⛔. Le programme utilise des *sockets* réseau ? ⛔. Ainsi, à part un programme bateau type "Hello World", on ne peut pas faire grand chose 😕. Seccompliqué cette histoire ... 

###  📝 Le mode filtrage (`SECCOMP_SET_MODE_FILTER`)

Bon je vous rassure, le précédent mode n'est (quasiment ?) plus utilisé. A la place on utilise plutôt le **mode filtrage** qui permet bien plus de flexibilité.

Ce mode permet de définir **des règles précises** indiquant quels appels système sont autorisés, refusés ou bloqués, ce qui rend **seccomp** plus adapté aux besoins d’une application.

Pour écrire une liste de règles nous utilisons des [BPF](https://fr.wikipedia.org/wiki/Berkeley_Packet_Filter) ou **Filtre de Paquets de Berkeley**. 

> Et ... le rapport avec Berkeley ?
{: .prompt-info }

Le nom **Berkeley Packet Filter (BPF)** tire son nom de l’**Université de Californie à Berkeley**, où il a été développé à la fin des années 1980. À l’origine, il a été conçu par des chercheurs de Berkeley pour **filtrer efficacement les paquets réseau** sans avoir à les copier inutilement entre le noyau et l’espace utilisateur. Le terme _Berkeley_ fait donc référence au **lieu de conception du projet**, et non à une technologie réseau en particulier 🤖.

De toute façon, la manière dont ces filtres sont mis en place ne nous intéresse pas particulièrement, puisque nous ne sommes pas dans un cours de développement sécurisé. En revanche, ce qui nous importe réellement est de savoir comment déterminer, lors de l’analyse d’un programme, si **l’exécution de tel ou tel appel système est autorisée ou non**.

## 📝 Les règles de filtrage

Pour ce faire, nous allons utiliser l'outil [seccomp-tools](https://github.com/david942j/seccomp-tools) qui permet notamment **d'extraire les règles de filtrage** BPF mises en place dans un programme en l'exécutant via l'option `dump`.

Si vous manipulez les programmes de ce chapitre via le conteneur Docker, l'outil `seccomp-tools` y est déjà installé.

> Si vous ne souhaitez pas exécuter le programme dont les règles de filtrage sont à extraire, il est possible d'utiliser l'option `disasm`. Néanmoins, il faudra extraire en amont le filtre BPF brut du programme.
{: .prompt-tip }

### Exemple de test

Prenons un exemple concret pour comprendre comment lire ces filtres. Voici le programme que nous utiliserons dans cet exemple :

```cpp
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <stddef.h>

/* Macros utilitaires simples */
#define SC_ALLOW(syscall) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, syscall, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

#define SC_KILL \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)


int install_seccomp(void)
{
    struct sock_filter filter[] = {
        /* Chargement du numero de l’appel systeme */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, nr)),

        /* Appels systeme autorises */
        SC_ALLOW(__NR_read),
        SC_ALLOW(__NR_write),
        SC_ALLOW(__NR_open),

        /* Gestion de la memoire (maximum 3) */
        SC_ALLOW(__NR_brk),
        SC_ALLOW(__NR_mmap),
        SC_ALLOW(__NR_munmap),

        /* Tout le reste est interdit */
        SC_KILL,
    };

    struct sock_fprog prog = {
        .len = sizeof(filter) / sizeof(filter[0]),
        .filter = filter,
    };

    /* Obligatoire pour installer un filtre seccomp */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("prctl(NO_NEW_PRIVS)");
        return -1;
    }

    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog)) {
        perror("seccomp");
        return -1;
    }

    return 0;
}

int main(void) {
    printf("[+] Installation du filtre seccomp\n");

    if (install_seccomp() < 0) {
        fprintf(stderr, "[-] Echec de l’installation de seccomp\n");
        exit(1);
    }

    printf("[+] Seccomp installe\n");
    printf("[+] Tentative d’execution de execve(\"/bin/sh\")...\n");

    char *argv[] = {"/bin/sh", NULL};
    char *envp[] = {NULL};

    execve("/bin/sh", argv, envp);

    /* Cette ligne ne sera JAMAIS atteinte */
    perror("execve");
    return 0;
}
```

Il n'est pas nécessaire de s'intéresser à la fonction `install_seccomp`. Ce programme implémente un filtre BPF grâce à **seccomp** via `syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog)`.

Normalement les commentaires ont dû vous aider à comprendre ce que fait le programme :

- autoriser **seulement 6** appels système ;
- tous les autres appels système sont **interdits**.

Accès au conteneur Docker :

- ⬇️ **Téléchargement** : [pwn-seccomp-exemple-1.zip](https://drive.proton.me/urls/598CKEJ90R#tt3ZwtWyvPPq)
- 🔎 **SHA256 & Analyse Virus Total** : [915fbaa0269f75f63d62428e3329f36a1c150d334bf16aaaca4de1e292ae20a7](https://www.virustotal.com/gui/file/915fbaa0269f75f63d62428e3329f36a1c150d334bf16aaaca4de1e292ae20a7)
- ⚙️ **Construction et lancement du conteneur** :

```sh
docker build -t pwn-seccomp-exemple-1 .

docker run -it --rm -p 1234:1234 --cap-add=SYS_PTRACE --security-opt seccomp=unconfined pwn-seccomp-exemple-1
```

Compilons le programme avec `gcc main.c -o exe` et exécutons-le :

```
$ ./exe

[+] Installation du filtre seccomp
[+] Seccomp installe
[+] Tentative d’execution de execve("/bin/sh")...
[1]    52597 invalid system call (core dumped)  ./exe
```

On pouvait s'y attendre : `execve` n'est pas exécuté. Le code de retour est le suivant :

```sh
echo $?
159
```

Or `159 == 128 + 31` où `31` est le *signum* de [SIGSYS: Bad system call](https://man7.org/linux/man-pages/man7/signal.7.html).

> Bah là c'est trivial de comprendre le filtre pourquoi a-t-on besoin d'utiliser un outil tel que `seccomp-tools` alors ?
{: .prompt-info }

Ici nous avons accès au code source. Avez-vous jeté un œil à **ce que donne la décompilation** de `install_seccomp` 🤯 ?

```cpp
__int64 __fastcall install_seccomp()
{
  __int64 v7; // [rsp+0h] [rbp-90h] BYREF
  // (...)
  unsigned __int64 v64; // [rsp+88h] [rbp-8h]

  v64 = __readfsqword(0x28u);
  
  v8 = 32;
  v9 = 0;
  v10 = 0;
  v11 = 0;
  v12 = 21;
  v13 = 0;
  v14 = 1;
  v15 = 0;
  v16 = 6;
  v17 = 0;
  v18 = 0;
  v19 = 0x7FFF0000;
  v20 = 21;
  v21 = 0;
  v22 = 1;
  v23 = 1;
  v24 = 6;
  v25 = 0;
  v26 = 0;
  v27 = 0x7FFF0000;
  v28 = 21;
  v29 = 0;
  v30 = 1;
  v31 = 2;
  v32 = 6;
  v33 = 0;
  v34 = 0;
  v35 = 0x7FFF0000;
  v36 = 21;
  v37 = 0;
  v38 = 1;
  v39 = 12;
  v40 = 6;
  v41 = 0;
  v42 = 0;
  v43 = 0x7FFF0000;
  v44 = 21;
  v45 = 0;
  v46 = 1;
  v47 = 9;
  v48 = 6;
  v49 = 0;
  v50 = 0;
  v51 = 0x7FFF0000;
  v52 = 21;
  v53 = 0;
  v54 = 1;
  v55 = 11;
  v56 = 6;
  v57 = 0;
  v58 = 0;
  v59 = 0x7FFF0000;
  v60 = 6;
  v61 = 0;
  v62 = 0;
  v63 = 0x80000000;
  LOWORD(v7) = 14;
  if ( prctl(38, 1, 0, 0, 0, a6, v7, &v8) )
  {
    perror("prctl(NO_NEW_PRIVS)");
    return 0xFFFFFFFFLL;
  }
  else if ( syscall(317, 1, 0, &v7) )
  {
    perror("seccomp");
    return 0xFFFFFFFFLL;
  }
  else
  {
    return 0;
  }
}
```

Je pense que l'on sera d'accord sur le fait qu'un outil permettant de les extraire automatiquement ne serait pas de refus 😉.

> `prctl(PR_SET_NO_NEW_PRIVS, (...))` doit toujours être appelé avant d'appliquer le filtre **seccomp**.
> 
> L'une des autres conséquence importante de `PR_SET_NO_NEW_PRIVS` est que le processus courant (et ses potentiels processus fils) ne pourront **pas gagner plus de privilèges** qui en avaient au moment de l'appel de `prctl(PR_SET_NO_NEW_PRIVS, (...))`.
> 
> Cela signifie notamment que les bits **SUID** et **SGID** seront **ignorés**. RIP 🙃.
{: .prompt-tip }

Utilisons la commande `seccomp-tools dump ./exe` pour extraire le filtrage mis en place :

```
$ seccomp-tools dump ./exe
[+] Installation du filtre seccomp
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0003
 0002: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0003: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0005
 0004: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0005: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0007
 0006: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0007: 0x15 0x00 0x01 0x0000000c  if (A != brk) goto 0009
 0008: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0009: 0x15 0x00 0x01 0x00000009  if (A != mmap) goto 0011
 0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0011: 0x15 0x00 0x01 0x0000000b  if (A != munmap) goto 0013
 0012: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0013: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
```

Nous remarquons tout d'abord la présence de la chaîne de caractères `[+] Installation du filtre seccomp` mais pas celle des autres. On en déduit que :

- le programme est **réellement exécuté** et les règles de filtrage **ne sont pas extraites statiquement** ;
- le programme n'est pas exécuté **dans son entièreté**. Son **exécution est arrêtée** au moment du `syscall` qui fait appel à `seccomp`.

Ensuite, pour comprendre le filtre mis en place il suffit de lire linéairement la partie à droite de haut en bas où `A` est le potentiel appel système à exécuter.

Lorsque l'appel système **a le droit d'être exécuté**, `ALLOW` est retourné. Lorsqu'il **n'a pas le droit d'être exécuté**, `KILL_PROCESS` est retourné.

> Oui mais là c'est facile, c'est un exemple bateau 😴 ...
{: .prompt-info }

Très bien. Analysons donc le cas d'un programme un peu plus connu.

### Exemple réel : chromium

Nous avons vu un peu plus haut que **chromium** utilise **seccomp** afin de renforcer sa sécurité. Nous devrions donc pouvoir en extraire le filtre **seccomp**, nan ? Tout d'abord installons-le. Pour les distributions basées sur Ubuntu/Debian cela peut se faire avec `sudo apt install chromium-browser`.

Ensuite, lançons le en arrière-plan sans utiliser la partie graphique : 

```
chromium --headless --disable-gpu &
[1] 52665
```

Utilisons `seccomp-tools` avec le PID de chromium :

```
seccomp-tools dump --pid 52665
```

Vous devriez normalement tomber sur une erreur de ce type :

```
[ERROR] Operation not permitted - ptrace attach failed
        PTRACE_SECCOMP_GET_FILTER requires CAP_SYS_ADMIN
        Try:
            sudo env "PATH=$PATH" seccomp-tools dump --pid 52665
```

Bon. Essayons avec la commande via `sudo` :

```
$ sudo env "PATH=$PATH" seccomp-tools dump --pid 52665

 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x12 0xc000003e  if (A != ARCH_X86_64) goto 0020
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x1d 0xffffffff  if (A != 0xffffffff) goto 0034
 0005: 0x15 0x00 0x03 0x00000125  if (A != pipe2) goto 0009
 0006: 0x20 0x00 0x00 0x0000001c  A = flags >> 32 # pipe2(fildes, flags)
 0007: 0x54 0x00 0x00 0x00000000  A &= 0x0
 0008: 0x15 0x0e 0x17 0x00000000  if (A == 0) goto 0023 else goto 0032
 0009: 0x15 0x00 0x16 0x00000010  if (A != ioctl) goto 0032
 0010: 0x20 0x00 0x00 0x0000001c  A = cmd >> 32 # ioctl(fd, cmd, arg)
 0011: 0x15 0x00 0x03 0x00000000  if (A != 0x0) goto 0015
 0012: 0x20 0x00 0x00 0x00000018  A = cmd # ioctl(fd, cmd, arg)
 0013: 0x15 0x13 0x00 0x0000541c  if (A == 0x541c) goto 0033
 0014: 0x15 0x12 0x00 0x00005412  if (A == 0x5412) goto 0033
 0015: 0x20 0x00 0x00 0x0000001c  A = cmd >> 32 # ioctl(fd, cmd, arg)
 0016: 0x54 0x00 0x00 0x00000000  A &= 0x0
 0017: 0x15 0x00 0x0e 0x00000000  if (A != 0) goto 0032
 0018: 0x20 0x00 0x00 0x00000018  A = cmd # ioctl(fd, cmd, arg)
 0019: 0x15 0x0d 0x0b 0x0000541c  if (A == 0x541c) goto 0033 else goto 0031
 0020: 0x15 0x00 0x0d 0x40000003  if (A != ARCH_I386) goto 0034
 0021: 0x20 0x00 0x00 0x00000000  A = sys_number
 0022: 0x15 0x00 0x03 0x0000014b  if (A != i386.pipe2) goto 0026
 0023: 0x20 0x00 0x00 0x00000018  A = args[1]
 0024: 0x54 0x00 0x00 0x00000080  A &= 0x80
 0025: 0x15 0x07 0x06 0x00000080  if (A == 128) goto 0033 else goto 0032
 0026: 0x15 0x00 0x05 0x00000036  if (A != i386.ioctl) goto 0032
 0027: 0x20 0x00 0x00 0x00000018  A = level # setsockopt(fd, level, optname, optval, optlen)
 0028: 0x15 0x04 0x00 0x0000541c  if (A == 0x541c) goto 0033
 0029: 0x15 0x03 0x00 0x0000541c  if (A == 0x541c) goto 0033
 0030: 0x15 0x02 0x00 0x00005412  if (A == 0x5412) goto 0033
 0031: 0x15 0x01 0x00 0x00005412  if (A == 0x5412) goto 0033
 0032: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0033: 0x06 0x00 0x00 0x0005000d  return ERRNO(13)
 0034: 0x06 0x00 0x00 0x00000000  return KILL
```

Et voilà 😎 ! Nous n'allons pas décortiquer le filtre utilisé par chromium néanmoins nous y reviendrons dans le prochain chapitre afin d’analyser les **erreurs d’implémentation** qui peuvent être présentes dans un filtre **seccomp**.

## 📋 Synthèse

Ce qui est pas mal quand on s'intéresse à **seccomp** du point de vue d'un attaquant, c'est que l'on a pas nécessairement besoin de comprendre comment l'implémenter en détails. 

En revanche, ce qui nous intéresse est de savoir comment **comprendre** et **lire le filtre seccomp** et ce que cela implique en termes de protection dans un programme. Ça tombe bien ! Voyons désormais comment tirer profit des vulnérabilités présentes dans un filtre **seccomp**.