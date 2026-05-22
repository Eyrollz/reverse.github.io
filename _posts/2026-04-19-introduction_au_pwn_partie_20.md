---
title: Partie 20 - Introduction à l’exploitation par ROP (1/6)
date: 2026-04-19 10:00:00
categories: [Pwn, Introduction au pwn]
tags: [x86, pwn, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# Introduction à l’exploitation par ROP (*Return-Oriented Programming*) (1/6)

![](/assets/images/introduction_au_pwn/rop_timeline.png)

Enfin nous y sommes ! En gravant petit-à-petit les marches de l'exploitation de binaires, nous sommes enfin arrivés à la technique d'exploitation qui est l'une des plus connues et l'une des plus utilisées, à savoir le **ROP** ou **Return-Oriented Programming**.

Cette technique est très utile lorsque :

- la **pile** n'est **pas exécutable** ;
- il n'est **pas possible** de faire un **ret2libc**.

Il est possible de considérer le **ROP** comme une **évolution** ou une **généralisation** du **ret2libc**, offrant davantage de flexibilité lors de l'exploitation.

## Introduction

Contrairement à ce que son nom indique, le **ROP** **n'est pas** lié à de la **programmation pure** ou du **développement** dans le sens où nous n'allons pas écrire des lignes de code. Il s'agit plutôt d'une technique qui consiste à **réutiliser des bouts de code**, plus précisément des instructions issues du programme exploité ou des bibliothèques qu'il utilise, afin de **contrôler l'exécution du programme** et atteindre un objectif en particulier comme exécuter un appel système ou des fonctions intéressantes (ex : `system`,`execve` ...).

Ainsi, au lieu de tenter d'appeler diverses fonctions dans leur **entièreté** sans trop contrôler ce qui s'y passe, nous faisons en sorte de **n'exécuter que les parties intéressantes** de celles-ci afin de réussir à exploiter le programme. 

Pour faire **l'analogie**, imaginez que les fonctions d'un programme soient des **casseroles**, en utilisant du ROP cela reviendrait à les utiliser de la sorte pour passer d'un bout de code à un autre :

![](/assets/images/introduction_au_pwn/gif_rop_bis 1.gif)

Généralement, un prérequis pour l'utilisation de cette technique est de **contrôler** `eip`/`rip` et, si possible, les **premiers éléments** de la pile.

## Fonctionnement du ROP

> Comment c'est possible de n'exécuter qu'une partie d'une fonction ? Et surtout comment passer d'un bout de code à un autre ?
{: .prompt-info }

C'est justement là que réside la magie du **ROP** : passer d'un bout de code à un autre sans que cela ne fasse planter le programme.

### Appeler une fonction avec les bons arguments

Pour comprendre plus facilement comment fonctionne le **ROP**, examinons le scénario suivant :

- il s'agit d'un programme SUID 32 bits ;
- dans le cadre d'un *buffer overflow* nous contrôlons `eip` ainsi que les `N` premiers éléments sur la pile ;
- nous avons un *leak* de la libc ;
- pour réussir l'exploit, il est nécessaire de devenir `root`.

Ainsi, il n'est pas possible de trifouiller le programme afin de lancer `system("/bin/sh")`. Nous avons besoin de quelque chose **d'un peu plus poussé** comme `execve("/bin/sh", ["/bin/sh","-p",NULL], NULL);` pour ne **pas perdre les droits** `root`.

Nous avons une fuite d'adresse de la **libc**, trouver l'adresse de `execve` sera donc assez facile. En revanche, faire en sorte d'avoir exactement ces arguments dans cet ordre, c'est un peu plus compliqué.

Le **ROP** nous permettra d'agencer petit à petit la **pile** en **32 bits** (ou les **registres** en **64 bits**) afin d'avoir les bons arguments aux bons endroits. Pour ce faire, nous allons utiliser ce que l'on appelle communément des **gadgets**.

Un **gadget** est un **fragment de code** composé de **plusieurs instructions**, qui permet de :

- **effectuer une action spécifique**, par exemple : placer la valeur `0x100` dans le registre `rdx`, ajouter `0x20` à `esp`, etc. ;
- **enchaîner vers un autre gadget** (ou une autre fonction) une fois son exécution terminée.

Généralement un seul gadget n'est pas suffisant pour agencer les arguments comme il le faut. C'est pourquoi on parle souvent de **chaîne de ROP** lorsqu'un programme est exploité via du **ROP** : **enchaîner plusieurs gadgets** jusqu'à pouvoir appeler correctement la fonction voulue.

### Passer d'un gadget à un autre

Les gadgets ont très souvent l'allure suivante :

```nasm
; instr
; ... 
; instr
ret
```

Les différentes instructions vont effectuer diverses actions avant d'arriver à l'instruction `ret`. Pour rappel, `ret` n'est rien d'autre qu'un `pop eip`.

Pour comprendre comment passer d'un gadget à un autre, imaginons que nous devions exploiter le programme suivant :

```cpp
// (...)
void goal()
{
    if (eax == 0x1337)
        ouvrir_shell();
    return;
}

int main()
{
 char buffer[8];
 gets(buffer);
 
 // (...)
 
 return 0;
}
```

Voici notre avancée lors de son exploitation :

- nous avons réussi à exploiter un *buffer overflow* dans le `main` (faisons abstraction du canari pour le moment) et nous pouvons contrôler le contenu du *buffer* sur la pile ;
- nous avons un leak du programme, de la libc etc. ;
- l'objectif est d'exécuter la fonction `goal` qui ouvre un *shell* seulement si `eax` vaut `0x1337`.

Nous avons trouvé quelques gadgets à droite, à gauche et voici ce que nous avons pu en faire :

![](/assets/images/introduction_au_pwn/rop_diagram.png)

1. lors du `ret` de la fonction vulnérable, nous avons pu exploiter le dépassement de mémoire afin de **contrôler** les **9 premiers éléments** de `esp` ;
2. il n'est pas nécessaire de savoir dans quelles fonctions se trouvent les gadgets que nous avons trouvés. L'essentiel est qu'ils permettent, chacun d'eux, de réaliser diverses actions pour atteindre, *in fine*, notre objectif. Chacun de ces gadgets va **consommer un certain nombre d'éléments** sur la pile en fonction des instructions qu'il exécute. Très souvent, les premiers éléments seront directement utilisés au sein du gadget tandis que le dernier sera **l'adresse vers le prochain gadget** ;
3. en contrôlant arbitrairement les **premiers éléments de la pile** ainsi que **l'ordre d'enchaînement des gadgets**, nous avons pu affecter à `eax` la valeur `0x1337` et exécuter avec succès la fonction `goal`.

La **disposition des différents éléments** sur la pile s'appelle une **chaîne de ROP**. Vous entendrez souvent parler de **construction** de chaîne de ROP. Il s'agit de trouver le bon **agencement** d'adresses de gadgets à insérer dans la pile afin d'exploiter le programme.

> On aurait pu faire bien plus simple en mettant `0x1337` sur la pile et en appelant un gadget  🟡 `pop edx ...` ?
{: .prompt-info }

Oui tout à fait. Cet enchaînement est utilisé à titre d'exemple pour comprendre comment **passer d'un gadget à un autre**, mais oui, nous aurions pu faire cela. 

La dernière étape du ROP n'est **pas toujours l'exécution d'une fonction**. Cela peut aussi être l'exécution d'un **appel système**.

> Et on est censés faire comment pour trouver des gadgets ? On a l'impression qu'ils étaient comme par magie présents dans le programme.
{: .prompt-info }

Ne vous inquiétez pas, nous allons en parler 😅.

### Comment trouver des gadgets dans un programme

**Plusieurs outils** ont vu le jour et permettent de **trouver facilement des gadgets** dans un programme. Les plus connus sont :

- [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) ;
- [xgadget](https://github.com/entropic-security/xgadget) ;
- [Ropper](https://github.com/sashs/Ropper).

Il en existe sûrement d'autres mais ceux-là font très bien l'affaire. Dans le cadre de ce cours, nous utiliserons **ROPgadget**.  Une fois installé, je vous propose d'utiliser le programme suivant pour apprendre à chercher des gadgets :

```cpp
#include <stdio.h>

int main()
{
  puts("C'est l'heeeeeure du du du du du ROP !");
  return 0;
}
```

Vous pouvez le compiler avec `gcc -m32 -no-pie -fno-pie  main.c -o exe`.

Accès au conteneur Docker :

- ⬇️ **Téléchargement** : [pwn-rop-exemple-1.zip](https://drive.proton.me/urls/R69KHMS3TR#TUyQhr848aHy)
- 🔎 **SHA256 & Analyse Virus Total** : [e24a86ddc1b4c5963a51921ce0a6a7c20af9f6433b630c13f23a63d2093a46f6](https://www.virustotal.com/gui/file/e24a86ddc1b4c5963a51921ce0a6a7c20af9f6433b630c13f23a63d2093a46f6)
- ⚙️ **Construction et lancement du conteneur** :

```sh
docker build -t pwn-rop-exemple-1 .

docker run -it --rm -p 1234:1234 --cap-add=SYS_PTRACE --security-opt seccomp=unconfined pwn-rop-exemple-1
```

> Voyons tout d'abord des exemples en 32 bits car il est généralement **plus facile** d'exploiter un programme avec du ROP en 32 bits qu'en 64 bits. 
> 
> En effet, en **32 bits** les arguments d'une fonction sont récupérés directement **depuis la pile**. Ce sont donc des valeurs que nous pouvons contrôler en utilisant un dépassement de mémoire par exemple.
> 
> En revanche, en **64 bits**, les premiers arguments sont récupérés **via les registres**. Il est donc nécessaire de trouver des gadgets permettant de **charger des valeurs arbitraires** dans `rdi`, `rsi` etc.
{: .prompt-tip }

Pour afficher les gadgets présents dans le programme, il est possible d'utiliser `ROPgadget --binary ./exe`. Vous devriez voir une très longue liste de gadgets qui s'affiche :

```
(...)
0x0804901e : pop ebx ; ret
0x08049191 : popal ; cld ; ret
0x08049036 : push 0 ; jmp 0x8049020
0x080490cb : push 0x804c010 ; call eax
0x08049118 : push 0x804c010 ; call edx
0x08049046 : push 8 ; jmp 0x8049020
0x08049162 : push ds ; sti ; jmp 0x80490f0
0x08049117 : push eax ; push 0x804c010 ; call edx
0x0804919f : push edi ; add byte ptr cs:[eax], al ; add esp, 8 ; pop ebx ; ret
0x08049077 : push esp ; mov ebx, dword ptr [esp] ; ret
0x0804900a : ret
(...)
```

Les **valeurs en hexadécimal** sont les **adresses** des différents gadgets. Si le programme avait été compilé avec PIE, l'outil afficherait les *offsets* auquel cas un *leak* aurait été requis afin de déterminer **l'adresse exacte d'un gadget**.

Vous remarquerez que certains gadgets ne finissent pas par une instruction `ret` mais par `jmp ...`. Les gadgets de ce type sont utilisés dans une technique dérivée du ROP qui est le **JOP** ou **Jump-Oriented Programming**.

Cela consiste à utiliser principalement des gadgets qui se terminent par une **instruction de saut** (`jmp 0x...`, `jnz 0x...`, `jmp eax` etc.). La **manière d'exploiter** un programme avec du **JOP** n'est pas la même qu'avec le **ROP**. Nous aurons l'occasion d'en discuter davantage dans un chapitre dédié.

Le JOP permet notamment de **ne plus dépendre** de la **pile** ni de **gadgets** se terminant par une instruction `ret`.

> **Astuce ROPgadget** : pour ne pas afficher les instructions terminées par un saut, il est possible d'utiliser l'option `--nojop`.
> 
> ⚠️ Cela supprimera également les gadgets terminés par des **appels indirects de fonctions** (ex : `call eax`, `call edx` ...) qui peuvent parfois s'avérer très utiles, au même titre que les instructions `jmp eax`, `jmp edx`... 
{: .prompt-tip }

### Des gadgets en veux-tu, en voilà

Comme vous pouvez le constater, il n'y a pas tant de gadgets que ça dans le programme : `Unique gadgets found: 98`. Ce qui est normal étant donné qu'il s'agit d'un **petit programme**. Dans les programmes **plus volumineux**, nous pourrons y trouver, logiquement, **plus de gadgets**.

Que dire si le programme est compilé statiquement ! Voici le nombre de gadgets du même programme compilé statiquement avec `gcc -m32 -no-pie -fno-pie  main.c -o exe -static` : `Unique gadgets found: 7893`. Pas mal non 😎 ?

> Effectivement il y en a plus mais la majorité des programmes ne sont pas compilés statiquement ...
{: .prompt-info }

C'est vrai. Mais cela n'est pas si embêtant que cela dans le cas suivant :

- une **fuite d'adresse** de la **libc** est disponible ;
- la **version exacte de la libc** utilisée est déterminée (nous pouvons donc la télécharger et y avoir accès).

Une fois ces conditions remplies, qu'est-ce qui nous empêche de lancer **ROPgadget** sur la **libc** ? Au final, même si elle est **PIE**, nous pourrons déterminer l'adresse exacte de chaque gadget et l'utiliser grâce au *leak*.

### L'utilité du ROP

> Si nous contrôlons les `N` premiers éléments de la pile, autant faire du **ret2libc**, c'est plus rapide ?
{: .prompt-info }

Dans plusieurs cas, la technique du **ret2libc** ou l'utilisation d'un **shellcode** montre ses limites :

- **pile non exécutable** : plus largement, lorsqu'il n'y a pas de zone mémoire avec les permissions RWX, il n'est pas possible d'utiliser directement un *shellcode*. Dans un tel cas, nous sommes généralement contraints de réutiliser du code d'ores et déjà présent dans le programme chargé en mémoire ;
- **pas de fuite de la libc** : si on ne parvient pas à obtenir un *leak* pour connaître l’emplacement exact d’une fonction dans la **libc**, impossible de faire un **ret2libc**.  Avec du **ROP**, on a un peu plus de liberté : par exemple, on peut appeler une fonction présente dans la **GOT** pour tenter d’obtenir une fuite d’adresse de la libc. Bien sûr, ça ne marche que si le programme n’est **pas compilé en PIE**, ou si on a déjà réussi à faire fuiter une adresse du programme lui-même ;
- **programme 64 bits** : sur les systèmes 64 bits, les arguments des fonctions sont passés dans les **registres**. De ce fait, avec un simple **ret2libc**, on ne peut pas charger ces registres juste en **les plaçant sur la pile sans utiliser de gadget**.

La liste n'est **pas exhaustive**, mais ce sont les limites que l'on rencontre le plus souvent.

### Au fait, d'où viennent ces instructions ?

> Y a un truc que je ne comprends pas. Comment se fait-il que **ROPgadget** retourne des instructions qui ne sont même pas visibles si j'affiche le code désassemblé du programme ?
{: .prompt-info }

C'est une excellente question et y répondre permet de comprendre comment le **ROP** permet d'exécuter des instructions qui, *a priori*, ne sont pas présentes dans le programme.

Pour y répondre, nous allons retourner à la composition d'une instruction : les **opcodes**. Prenons par exemple les instructions suivantes que l'on pourrait trouver en fin de fonction :

```nasm
0x4006A0 41 5E    pop     r14
0x4006A2 41 5F    pop     r15
0x4006A4 C3       retn
```

Vous êtes d'accord que l'intervalle d'octets `[0x4006A0;0x4006A4]` est exécutable en mémoire ? Voici ce que donne le désassemblage non pas à partir de l'adresse `0x4006A0` mais plutôt `0x4006A1` :

```nasm
0x4006A1 5E       pop     rsi
0x4006A2 41 5F    pop     r15
0x4006A4 C3       retn
```

On obtient la possibilité de charger le registre `rsi` 🤩. Et c'est pas fini ! Ci-dessous, le désassemblage réalisé à partir de `0x4006A3` :

```nasm
0x4006A3 5F       pop     rdi
0x4006A4 C3       retn
```

Même `rdi` y passe, pas mal non 😎 ? Comme l’assembleur **x86/x86_64** est de type **CISC**, il n’y a pas de **contrainte stricte d’alignement** ni de **taille fixe** : une instruction peut être codée sur **1**, **2**, **3** voire jusqu’à **15 octets**.

Ainsi, en commençant à désassembler à partir d'une adresse plutôt qu'une autre, il est possible d'avoir des **instructions différentes** alors que les **octets présents dans le programme** n'ont pas changé.

## 📋 Synthèse

Voici une synthèse des principaux points que l'on a vus au cours de ce chapitre :

- le **ROP** (**Return-Oriented Programming**) consiste à **réutiliser de petits fragments** de code déjà présents (**les gadgets**) pour composer ce que l'on appelle "**une chaîne de ROP**" et prendre le contrôle de l’exécution du programme ;
- **Pourquoi on l’utilise ?** Quand la pile n’est **pas exécutable** ou que le **ret2libc** ne suffit pas, le **ROP** permet **d’appeler des fonctions**, d'exécuter des **appels système** etc.
- le **ROP** repose sur le **contrôle du pointeur d’instruction via la pile** ;
- un gadget est une **courte séquence d’instructions** se terminant souvent par un `ret` (ou `jmp`/`call`). En contrôlant la pile, on **agence les adresses des gadgets** et de certaines **valeurs** pour réaliser des actions complexes étape par étape ;
- en 32 bits les arguments sont issus de la pile. En 64 bits, les arguments passent par des registres (`rdi`, `rsi`, …) qui ne sont pas chargés automatiquement depuis la pile. En utilisant certains gadgets (`pop rdi`, `mov rdi, rxx` ...) il est possible de **contrôler les valeurs chargées dans les registres** utilisés comme paramètres de fonction ;
- certains outils comme **ROPgadget** ou **Ropper** permettent d'afficher les gadgets présents dans un programme. Conjugué à une bonne utilisation de `grep`, il est possible de trouver les gadgets adéquats.