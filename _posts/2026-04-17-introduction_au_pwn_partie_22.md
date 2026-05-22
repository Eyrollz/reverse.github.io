---
title: Partie 22 - Exploiter un binaire par ROP - techniques avancées et cas particuliers (3/6)
date: 2026-04-17 10:00:00
categories: [Pwn, Introduction au pwn]
tags: [x86, pwn, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# Exploiter un binaire par ROP : techniques avancées et cas particuliers (3/6)

J'espère que les précédents exercices ne vous ont pas trop donné de fil à retordre. Comme vous avez pu le constater, le ROP en soi n'est pas une technique très compliquée. Ce qui est compliqué, c'est de :

- **trouver les gadgets** ;
- faire en sorte que leur exécution se déroule **correctement**.

Nous avons, lors du précédent chapitre, exploité un programme grâce à une chaîne de ROP dans un contexte qui nous était favorable :

- nous avions un *leak* ;
- le *buffer* était assez grand pour contenir toute la chaîne de ROP ;
	- il n'y avait pas de contrainte sur les données écrites dans le *buffer* (exemple : sauts de ligne ou espaces autorisés ...).

Nous allons essayer, à travers ce chapitre, de pousser le bouchon de plus en plus loin.

##   ROP 32 bits VS ROP 64 bits

Il existe plusieurs différences importantes entre le **ROP 32 bits** et le **ROP 64 bits**. Voyons ensemble en quoi elles consistent.

### 64 bits

Etant donné que les premiers arguments des programmes **x86_64** sont transmis via des registres, la **structure d'une chaîne de ROP** sera généralement de la sorte :

![](/assets/images/introduction_au_pwn/x64_rop_chain.png)

Dans ce schéma il n'y a qu'une seule fonction à exécuter : `goal`. Qu'en serait-il s’il fallait exécuter plusieurs fonctions intermédiaires avant `goal` ?

![](/assets/images/introduction_au_pwn/funcs_rop_64_bis.png)

La structure est assez logique, elle est de cette forme :

```
gadget_X

arg_1
...
arg_N

func_X
```

Où `gadget_X` est un **ensemble d'instructions** qui permet de charger les divers arguments de `func_X` dans les registres idoines. Ces gadgets ont souvent la forme `pop rxx ; pop rxx ; ... ; ret`. 

### 32 bits

Les **chaînes de ROP en 32 bits** ont une structure différente de celles en 64 bits pour deux principales raisons :

1. **les arguments sont transmis via la pile** : cela implique que l'adresse de la fonction précède les arguments dans la chaîne de ROP alors qu'en 64 bits, **c'est l'inverse** ;
2. **la convention d'appel doit être prise en considération** : les fonctions peuvent avoir une [convention d'appel](https://reverse.zip/posts/introduction_au_reverse_partie_17/#-les-conventions-dappel ) (ex : `cdecl`) qui fait que c'est à la **fonction appelante de rétablir la pile**. Auquel cas, il faudra ajouter des "**gadgets de nettoyage**" dans la chaîne de ROP afin que les appels consécutifs de fonctions se déroulent sans soucis.

Les fonctions de la **libc** sont principalement de type `cdecl`. Ce qui signifie que c'est à nous de faire le ménage 🧹.

En reprenant la précédente image qui schématise **l'enchaînement de l'appel de 4 fonctions**, voici ce que cela donnerait en **32 bits** en comparant avec la version **64 bits** :

![](/assets/images/introduction_au_pwn/ROP_64_32.png)

L’agencement global reste identique : les fonctions sont appelées dans **le même ordre** ; la différence se situe dans la disposition des **gadgets** et la préparation des **arguments**.

> Les gadgets utilisés en **32 bits** n'ont **pas le même objectif** qu'en **64 bits** :
> 
> **64 bits** : les gadgets permettent de **charger les arguments** dans les registres (ex : `pop rdi ; pop rsi ; pop rdx ; ret`).
> 
> **32 bits** : les gadgets permettent de **faire le ménage** 🧹 avant de passer à la fonction suivante. Cela consiste principalement à retirer les arguments de la pile avec des gadgets du type : `pop exx ; pop exx ; pop exx ; ret`.
{: .prompt-warning }

En 64 bits l'appel d'une fonction est réalisé avec cet agencement :

```
adresse_gadget 
arg_1
...
arg_N
addr_fonction
```

En 32 bits, l'adresse de la fonction précède l'adresse du gadget :

```
addr_fonction
adresse_gadget
arg_1
...
arg_N
```

Pour résumer, la **position** du gadget et son **utilité** sont les suivantes :

- **64 bits** : le gadget est placé **avant la fonction** et avant les arguments car son rôle est de **charger les divers arguments** dans les registres ;
- **32 bits** : le gadget est placé **après la fonction** et avant les arguments car son rôle est de **retirer de la pile les arguments** qui viennent d'être utilisés.

Il n'y a **pas besoin d'apprendre** par cœur comment est effectué l'agencement interne en 64 bits ou 32 bits. Il suffit juste de se rappeler de **la manière dont sont réalisés les appels** dans ces deux architectures. Ensuite, il sera assez simple de retrouver comment agencer les différents éléments car cela suit une certaine **logique**.

> En 32 bits, l'adresse située en dessous de la dernière fonction exécutée (notée `OSEF` dans le schéma) peut valoir n'importe quelle valeur car une fois la fonction `goal` exécutée, l'exploitation du programme est terminée.
> 
> Par contre, vous pouvez modifier cette adresse pour la faire pointer vers une fonction comme `exit` afin de **quitter proprement** le programme.
{: .prompt-tip }

Un avantage des chaînes de ROP en 32 bits est qu'elles n'ont *a priori* **pas besoin d'être alignées** sur **N octets** contrairement aux chaînes de ROP 64 bits qui en ont souvent besoin.

## Stack pivot (ou pivot de pile 🥖)

Comment parler du ROP sans évoquer la technique du pivot de *stack* ? Nous l'avions brièvement évoquée dans le précédent chapitre lorsque nous avions parlé des **gadgets se terminant** par un `leave ; ret`.

Très souvent on cherche à éviter de tomber sur des gadgets se terminant par `leave ; ret` car cela chamboule toute la chaîne de ROP étant donné que `leave` modifie la valeur de `rsp`. Mais il existe **un cas où cela se révèle très pertinent**.

Pour illustrer cela, nous allons nous appuyer sur le programme suivant :

```cpp
#include <stdio.h>
#include <unistd.h>

// gcc -no-pie -fno-pie -fno-stack-protector main.c -o exe

char description[0x100];

int main()
{
    char prenom[0x10] = {0};

    puts("Quel est ton prenom ?");
    read(0,prenom,0x20);

    puts("Que fais-tu dans la vie ?");
    read(0,description,sizeof(description));

    puts("Merci c'est note, au revoir !");

    return 0;
}
```

En provoquant un dépassement de mémoire, les `0x18` premiers octets lus n'auront aucun effet sur le ROP. Avec les `8` octets restants, nous ne pouvons pas mettre en place une chaîne de ROP.

De plus la description n'est pas lue dans la pile. Nous avons donc besoin de plus de place. C'est là que le gadget `leave ; ret` intervient. Pour rappel, cela équivaut à :

```nasm
mov rsp, rbp
pop rbp
ret
```

### Contrôler `rsp`

Nous allons détourner l'utilisation classique de `leave ; ret` afin de pouvoir **déplacer la pile vers une autre zone mémoire**, généralement **connue d'avance** et où nous pouvons y **écrire des données arbitraires**.

**TL;DR** : cette technique permet de contrôler arbitrairement `rsp` et donc de modifier la zone de la pile.

Si vous vous souvenez de la manière de retourner vers la fonction appelante depuis la fonction appelée et de l'épilogue, vous devriez savoir qu'en **fin de fonction** la pile a peu ou prou cette forme :

![](/assets/images/introduction_au_pwn/stack_frames_bis.png)

Dans le cas d'un *buffer overflow*, lorsque la fonction appelée exécutera `leave ; ret`, au lieu de retourner dans la fonction appelante, cela impliquera deux choses :

- la **valeur sauvegardée** de `rbp` sera **écrasée** (ex: `0xdeadbeefcafebabe`) ;
- l'**adresse de retour** sera également **écrasée** (avec l'adresse d'un gadget etc.).

C'est un peu le but du *buffer overflow*, me diriez-vous ? 

Mais que se passerait-il si l'**adresse de retour** était écrasée avec **l'adresse du gadget** `leave ; ret` ?

![](/assets/images/introduction_au_pwn/leave_ret_bis.png)

1. Ceci est l'état de la **stack frame** une fois le *buffer overflow* réalisé mais avant de quitter la fonction exploitée ;
2. lorsque la fonction exploitée tente de retourner vers la fonction appelante, deux choses se passent :
	- `rbp` est chargé avec une valeur arbitraire `0xdeadbeefcafebabe` ;
	- le programme exécutera en réalité le prochain gadget, à savoir `leave ; ret`.
3. lors de l'exécution du gadget, on remarque que `rsp` a désormais la valeur arbitrairement choisie ! Toutefois, le programme ne risque pas d'aller bien loin : étant donné que `rsp` pointe vers une adresse invalide (`0xdeadbeefcafebabe`) l'instruction `pop rbp` échouera.

### Pivotons !

Nous savons à présent comment utiliser ce gadget pour contrôler `rsp`. Reprenons le programme utilisé à titre d'exemple pour voir en quoi un **pivot de pile** nous aiderait à pouvoir utiliser une **chaîne de ROP plus longue**.

Supposons que le tableau `description` soit stocké à l'adresse `0x404100` (car pas de PIE). Voici comment **rediriger** `rsp` vers le tableau `description` pour y **exécuter la chaîne de ROP** qu'il contient :

![](/assets/images/introduction_au_pwn/pivot_De_pile.png)
Il suffit d'exécuter **deux fois** le gadget `leave ; ret` !

> Notez bien que `rsp` pointera *in fine* à l'adresse choisie `+8` en raison du `pop rbp` du gadget `leave_ret`.
{: .prompt-tip }

L'un des atouts majeurs de cette technique est que même s'il n'est **pas possible** d'écraser des éléments dans la pile **au-delà de l'adresse de retour**, on peut tout-à-fait réaliser du **ROP** à partir d'une **autre zone mémoire contrôlée**.

> Et si je trouve pas de gadget `leave ; ret`, comment faire ?
{: .prompt-info }

Dans un tel cas, il suffit d'utiliser des instructions qui auront pour effet de modifier la valeur de `rsp` comme :

- `pop rsp` ;
- `xchg rsp, ...` ou `xchg ..., rsp` ;

Et si même comme ça vous ne trouvez pas de tels gadgets, on pourra envisager **l'utilisation de la fonction** [setcontext](/posts/exploitation_de_la_heap_partie_12/#setcontext). Cela nécessite cependant de contrôler le premier argument.

### ✏️ Exercice

Assez parlé, place au concret. C'est l'occasion que vous puissiez mettre en oeuvre cette technique dans le cadre d'un exercice, qui honnêtement, est facile à exploiter. Il suffit juste de bien avoir en tête la manière dont on veut pivoter de la pile vers une autre zone mémoire.

- 🎯 **Objectif** : appeler `ouvrir_shell` avec les arguments suivants `ouvrir_shell("/bin/sh", ["/bin/sh",NULL])` via un pivot de pile
- 🖥️ **Compilation** (si besoin de le faire en local) : `gcc -no-pie -fno-pie -fno-stack-protector main.c -o exe`
- ⬇️ **Téléchargement** : [pwn-rop-exo-pivot.zip](https://drive.proton.me/urls/3VVG56S1D4#2B2qjiR7i1yq)
- 🔎 **SHA256 & Analyse Virus Total** : [18313ff1267fd328db21b51bd239b5806f15a81c2164ea704b5b353b26f0c6e4](https://www.virustotal.com/gui/file/18313ff1267fd328db21b51bd239b5806f15a81c2164ea704b5b353b26f0c6e4)
- ⚙️ **Construction et lancement du conteneur** :

```sh
docker build -t pwn-rop-exo-pivot .

docker run -it --rm -p 1234:1234 --cap-add=SYS_PTRACE --security-opt seccomp=unconfined pwn-rop-exo-pivot
```

Le programme vulnérable est le suivant :

```cpp
#include <stdio.h>
#include <unistd.h>

// gcc -no-pie -fno-pie -fno-stack-protector main.c -o exe

char osef1[0x10000];
char description[0x100];
char osef2[0x10000];

void __attribute__((naked)) c_est_la_maison_qui_regale() 
{
    __asm__ volatile (
        "pop %rax\n\t"
        "pop %rbx\n\t"
        "pop %rdi\n\t"
        "pop %rdx\n\t"
        "pop %rsi\n\t"
        "ret\n\t"
    );
}

void ouvrir_shell(char * cmd, char **args)
{
    execve(cmd,args,NULL);
}

int main()
{
    char prenom[0x10] = {0};

    puts("Quel est ton prenom ?");
    read(0,prenom,0x20);

    puts("Que fais-tu dans la vie ?");
    read(0,description,sizeof(description));

    puts("Merci c'est note, au revoir !");

    return 0;
}
```

> Les tableaux `osef1` et `osef2` ne sont pas à utiliser lors de l'exploitation du programme. Ils permettent simplement d'éviter les soucis dans le cas où, lors de l'appel à `execve`, `rsp` recule beaucoup par rapport à l'adresse de `description`.
> 
> En fait, si on avait seulement mis le tableau `description` tout seul, en faisant `sub rsp, 0x100` par exemple, `rsp` pointerait vers une zone mémoire en **lecture seule** ce qui générera un `SIGSEGV`.
{: .prompt-tip }

## Etre à court de gadgets

Dans certains programmes, notamment les plus petits, il n'y a pas énormément de fonctions donc **pas beaucoup d'instructions** et donc **pas beaucoup de gadgets**. Par ailleurs, un *leak* de la **libc** n'est pas toujours disponible en début d'exploitation, donc on ne pourra pas compter sur les nombreux gadgets qu'elle propose.

Dans cette section, nous allons voir quelques astuces qui permettent d'arriver à ses fins lorsqu'il n'y a pas tant de gadgets que ça.

### `ret2csu` : utiliser `__libc_csu_init` comme gadget

#### `pop rdx` où es-tu ? 

Le fait est qu'il est généralement **assez facile** de trouver des gadgets ayant un `pop rdi` ou `pop rsi`. Par contre, c'est bien **plus rare pour** `pop rdx`. C'est assez embêtant, surtout lorsque l'on souhaite appeler une fonction qui prend **3 arguments**.

Il existe une **astuce** basée sur une utilisation détournée de `__libc_csu_init` qui permet de charger le registre `rdx`. Malheureusement cette fonction **n'existe plus** dans les **versions récentes** de la **libc**.

#### Que permet-elle de faire ?

Le corps de cette fonction ressemble à ceci :

![](/assets/images/introduction_au_pwn/libc_csu_init.png)

> Les registres utilisés peuvent différer d'un compilateur à un autre.
{: .prompt-tip }

1. cette instruction permet de charger `rdx` à partir de `r15`. Ça tombe bien, on peut modifier le contenu de `r15` avec le gadget `pop r15 ; ret` en fin de fonction 😉 ;
2. Nous avons [déjà parlé de ce fabuleux "gogo-gadget"](/posts/introduction_au_pwn_partie_20/#au-fait-doù-viennent-ces-instructions-) dont on peut extraire un `pop rdi ; ret` et `pop rsi ; pop r15 ; ret` 😎 ;
3. ah là, c'est un peu plus pénible. Il y a un **appel indirect** à l'adresse stockée dans le pointeur `[r12+rbx*8]`. Mais Dieu merci, nous pouvons contrôler le contenu de ces deux registres grâce aux dernières instructions de cette fonction.

Il y a aussi **une autre contrainte** qui est d'avoir `rbp == rbx` lors de l'instruction `cmp rbp, rbx`. Le cas échéant , l'instruction `jnz` fera sauter le programme encore une fois à l'instruction `mov rdx, r15` et ce n'est pas ce que l'on veut. Il est très facile de satisfaire cette contrainte étant donné que l'on peut **contrôler le contenu de ces deux registres** grâce à `pop rbx ; pop rbp ; ...; ret`.

La **seule difficulté** à surmonter dans l'utilisation de `__libc_csu_init` est de trouver un **pointeur qui pointe vers une fonction** qui ne fait ... rien, walou, nada. Bah oui, si la fonction appelée modifie `rdx` notre effort aura été vain 😅.

Nous pouvons opter pour **deux solutions** :

1. utiliser une **primitive d'écriture arbitraire** à une adresse connue d'avance et y écrire l'adresse d'une instruction `ret` ;
2. **chercher** parmi les fonctions qui disposent de symboles, celles qui **ne font rien**.

La première configuration implique **plus d'hypothèse** mais au moins, on peut choisir de n'exécuter que l'instruction `ret` d'une fonction, ni plus, ni moins.

Dans le second cas, on pourra chercher des fonctions de ce type (aussi appelée fonction `_fini`):

![](/assets/images/introduction_au_pwn/term_proc.png)

> `_term_proc` peut également être appelée `_fini`.
{: .prompt-tip }

Elle ne fait rien de spécial et dispose d'un entrée `Elf64_Sym` : 

![](/assets/images/introduction_au_pwn/elf_sym_fini.png)

En faisant en sorte que `r12+rbx*8 == 0x4003b0`, la fonction appelée sera `_term_proc` à l'adresse `0x4006b4`.

#### Chaîne de ROP finale

Comment écrire sa **chaîne de ROP** en utilisant `__libc_csu_init` pour réaliser, par exemple, un appel à une fonction `func(0xaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbb,0xcccccccccccccccc)` ?

![](/assets/images/introduction_au_pwn/rop_libc_csu_init_bis.png)

> L'image est très grande, n'hésitez pas à zoomer si besoin 🔎.
{: .prompt-tip }

Quelques remarques :

- il y a **pas mal d'étapes** mais au moins cela a le mérite de pouvoir exécuter **n'importe quelle fonction à 3 paramètres** ;
- la chaîne de ROP nécessite toutefois d'avoir **une taille assez importante** comme vous pouvez le constater 😅 ;
- `rbx` n'est pas mis dès le départ à la même valeur que `rbp` en raison de l'exécution de `add rbx, 0x1` ;
- sachant qu'il est possible d'affecter n'importe quelle valeur à `rsi` à partir de `r14`, il n'y a **pas besoin** d'ajouter dans la chaîne **un saut au gadget** `pop rsi ; pop r15 ; ret` ;
- évidemment, tous ces gadgets **sont présent dans la fonction** `__libc_csu_init`;
- les éléments `osef` peuvent contenir **n'importe quelle valeur** sans que cela n'ait d'effet lors du ROP.

Elle en a dans le ventre `__libc_csu_init`, hein 😏 ?

### Tirer parti des effets de bord

Il y a une **astuce**, un peu tirée par les cheveux, qui permet de **charger certains registres** en **appelant une fonction** donnée avec certains paramètres.

Par exemple, imaginons que vous n'ayez pas accès à la **libc** mais que le programme contienne un gadget `syscall` vous permettant de réaliser des appels système tels que `execve`. En **x86_64**, le numéro de l'appel système doit être renseigné dans le registre `rax`. Malheureusement, les gadgets contenant `pop rax ; ... ; ret` y'en a pas des masses. 

Pour parvenir à modifier arbitrairement le contenu de `rax`, nous allons utiliser **les effets de bords liés à l'exécution d'une fonction**, notamment la **modifications des registres**.

Par exemple, si on arrive à contrôler `rdi` et `rdx`, en appelant `memcpy` avec `rdx == 0`, peu importe la valeur de `rdi` (même s'il ne s'agit pas d'une adresse valide), `rax` aura la valeur de `rdi` en fin de fonction.

Ce qui signifie qu'en utilisant une taille nulle, il est possible de transférer la valeur de `rdi` à `rax`. Voici ce qui se passe avant et après un appel à `memcpy(0xaaaaaaaaaaaaaaaa, 0xbbbbbbbbbbbbbbbb, 0)` :

![](/assets/images/introduction_au_pwn/memcpy_rop.png)

Une fois l'exécution terminée :

![](/assets/images/introduction_au_pwn/rop_memcpy_2.png)

La valeur de `rax` est bien modifiée à partir de celle de `rdi` 😎.

> La valeur de `rsi` n'importe pas. Qu'elle soit valide ou non, dans tous les cas le contenu de `rdi` est chargé dans `rax`.
{: .prompt-tip }

Il devrait être possible d'exploiter cet effet de bord via des fonctions qui appellent `memcpy` de manière **sous-jacente** ou qui, comme `memcpy`, retournent dans tous les cas l'un des pointeurs donné en paramètre (ex : `memset` ...).

[Apparemment](https://www.scs.stanford.edu/~sorbo/brop/bittau-brop.pdf) `strcmp` chargerait `rdx` avec la taille de la chaîne de caractères comparée mais je n'ai pas vu que c'était toujours le cas ...

Il me semble qu'il y a aussi un effet de bord avec `calloc` (qui permet de charger `ecx` ou `rcx` ?) mais je ne m'en rappelle plus. Désolé de ne pas pouvoir vous en proposer plus 😕.

L’important à retenir est que ce type d’astuces est utile pour les situations où vous manquez vraiment de gadgets pour l'exploitation.

## ROP rime forcément avec *buffer overflow* ?

Vous vous dites sans doute que le **ROP** ne peut être utilisé que dans le cas où la vulnérabilité exploitée est un **dépassement de mémoire dans la pile**. Ce n'est pas totalement vrai. En fait, il est parfois possible de rediriger l'exploitation d'une vulnérabilité qui a lieu ailleurs grâce à différentes **astuces**. Dans tous les cas, nous partirons de l'hypothèse que nous possédons une **primitive d'écriture arbitraire**.

**La première astuce** est évidemment de réussir à avoir une **fuite de mémoire** (via une primitive de lecture, une chaîne de format ...) qui donne accès à des adresses de la pile afin de contourner l'**ASLR**. Ainsi, nous pourrons utiliser la primitive afin d'écrire une chaîne de **ROP** directement sur la pile.

Dans le cas où il ne semble pas être facile de faire fuiter une adresse de la pile, nous pourrons tenter d'**afficher le contenu de la variable globale** de la **libc** `environ` qui pointe vers les variables d'environnement situées ... **dans la pile** !

Il risque d'y avoir un peu de manipulation et de marge à prévoir pour trouver où pointe `rsp`/`esp` mais cela reste faisable.

## 📋 Synthèse

Ce chapitre un peu "fourre-tout" avait pour objectif de mettre en avant certaines problématiques et enjeux autour du **ROP**. Que ce soit de passer du **ROP 32 bits** au **ROP 64 bits** ou bien comment avancer lorsque l'on ne trouve pas les gadgets dont on a besoin. On retiendra que le plus important est d'avoir de l'imagination et de ne pas baisser les bras 💪.

Nous avons vu comment utiliser **ROPgadget** mais n'hésitez pas à jeter un œil à [Ropper](https://github.com/sashs/Ropper) qui propose des fonctionnalités intéressantes comme la recherche de gadget à partir de **contraintes** en utilisant un **solveur**.

Il y a également des outils, dont **ROPgadget**, **pwntools** et **Ropper**, qui permettent de construire **automatiquement** toute une **chaîne de ROP** pour exécuter l'appel d'une **fonction arbitraire** mais bon, ça ne semble fonctionner que dans les cas les plus simples 😶 ...

### Pratiquer davantage 💪

A ce stade, n'hésitez pas à vous entraîner au **ROP** car il s'agit d'une technique, à l'heure de l'écriture de ces lignes, toujours très utilisée pour exploiter les programmes. Voici quelques plateformes :

- [ROP Emporium](https://ropemporium.com/) : comme son nom l'indique, cette plateforme est spécialisée dans les challenges d'apprentissage du ROP. Je ne les ai pas testés mais ce qui semble intéressant est l'accessibilité des challenges, notamment des premiers. De plus, il y a la possibilité de choisir une architecture différente de x86_64 pour les plus curieux 😉.
- [Root-Me](https://www.root-me.org/fr/Challenges/App-Systeme/) : la catégorie "App Système" est en fait la catégorie de challenges de type *pwn*. Vous y trouverez pas mal de challenge qui peuvent être résolus via du ROP. 


