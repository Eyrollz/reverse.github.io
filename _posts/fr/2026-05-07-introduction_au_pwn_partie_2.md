---
title: Partie 2 - Rappels - chargement et exécution d’un programme en mémoire
date: 2026-05-07 10:00:00
categories: [Pwn, Introduction au pwn]
tags: [x86, pwn, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# Rappels : chargement et exécution d’un programme en mémoire

Il existe **différents types** de vulnérabilités qui peuvent être présents dans un programme tout comme il existe **différentes manières** de les exploiter. Néanmoins, on constate que tous les exploits ont un point commun : il est nécessaire, à un moment ou un autre, de **contrôler** `rip` (ou `eip` en 32 bits).

Comme vous le savez, `rip` est le registre qui **pointe vers l'instruction courante**. Ainsi, si on arrive à modifier la valeur de `rip` pour la faire pointer vers des **instructions que l'on contrôle**, nous pouvons faire exécuter n'importe quelle instruction au processeur et donc **manipuler le programme** à notre guise.

Après tout, le processeur n'est pas très intelligent : il ne fait qu'**exécuter les instructions** qui sont pointées par `rip` sans se poser trop de questions.

> Mais comment on peut contrôler `rip` alors qu'il n'existe pas d'instruction du type `mov rip, xxx` ?
{: .prompt-info }

Justement, en **tirant parti** de certains mécanismes inhérents au fonctionnement d'un programme (gestion de la pile, gestion de certains pointeurs de fonction...), nous pouvons faire en sorte de **contrôler indirectement** `rip`. 

Pour comprendre comment cela est possible, revoyons ensemble quelques rappels sur le **fonctionnement d'un programme**.

## Le programme utilisé

> N'hésitez pas à jeter un œil au chapitre "**Le fonctionnement d'un programme**" [partie 1](https://reverse.zip/posts/introduction_au_reverse_partie_2/) et [partie 2](https://reverse.zip/posts/introduction_au_reverse_partie_3/) du **cours de reverse** si des points vous paraissent flous ou si vous avez quelques lacunes 😉.
{: .prompt-tip }

A ce stade vous avez normalement déjà la **partie théorique** en tête. Je vous propose de regarder ce que cela donne **concrètement** plutôt que de revoir encore une fois des notions que nous avons déjà explicitées auparavant.

Utilisons ce programme :

```cpp
#include "stdio.h"  
#include "stdlib.h"  
#include "string.h"  
  
int var_globale_non_initialisee;  
int var_globale_initialisee = 0x213;  
char global_str[] = "Veuillez saisir votre nom";  
  
int main(int argc, char **argv)  
{  
  
 int var_locale = 2;  
    
 if (argc != var_locale)  
 {  
   puts(global_str);  
   return -1;  
 }  
  
 char *prenom = (char*) malloc(strlen(argv[1]));  
 strcpy(prenom,argv[1]);  
  
 printf("[+] Bonjour %s !\n",prenom);  
  
 return 0;  
}
```

Pour le compiler, utilisons la commande : `gcc -no-pie -fno-pie main.c -o exe`.

> Lors de la compilation, nous utilisons les options `-no-pie` et  `-fno-pie` afin de désactiver la protection **PIE** (**Position Independant Executable**). Il s'agit d'une protection qui permet de ne pas toujours charger les **données** et les **instructions** aux mêmes adresses mémoire d'une exécution à une autre.
> 
> Nous aurons l'occasion de nous pencher **plus en détails** sur cette protection. Pour l'instant, faisons-en abstraction 🫣.
{: .prompt-tip }

## Analyse statique

Avant d'analyser le programme lors de son exécution, essayons de **l'analyser en statique**.

Tout d'abord, en utilisant `file exe`, nous obtenons `ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=f6c6273992d3edadb19ae9e819a1897342579afd, for GNU/Linux 3.2.0, not stripped`.

On en déduit que :
- le programme est **compilé dynamiquement** : les bibliothèques nécessaires au fonctionnement du programme ne sont pas directement contenues dans le programme mais chargées lors de son exécution ;
- `interpreter` indique le chemin vers `ld` : `ld` est un programme qui s'occupe de **charger dynamiquement les bibliothèques** nécessaires à notre programme lorsque l'on le lance.

Pour l'instant, rien de nouveau sous le soleil. Ouvrons notre programme fraîchement compilé **dans IDA**.

> Vous pouvez évidemment ouvrir le programme avec le décompilateur de votre choix. Que ce soit IDA Freeware, Ghidra, Binary Ninja ou autre, les informations que nous allons voir sont présentes dans chacun d'eux.
> 
> Choisissez l'outil avec lequel vous êtes le plus à l'aise même si lors de ce cours nous allons **principalement manipuler IDA**.
{: .prompt-tip }

Étant donné que nous ne sommes pas dans un cours purement axé sur le *reverse*, nous n'allons pas nous **attarder sur la compréhension** du code décompilé ni de l'assembleur. Par contre, voyons ensemble **où se situent les différentes variables** de notre programme.

Après avoir exploré le programme, voici ce que l'on constate concernant la **localisation de ces variables en mémoire** :

![](/assets/images/introduction_au_pwn/localisation_variables_3.png)

> Si vous n'avez **pas les mêmes adresses**, c'est normal : d'un compilateur à un autre, il peut y avoir des différences de résultat pour un même code en entrée.
> 
> De la même manière, lorsque nous allons analyser des processus dans un débogueur, il est possible que vous n'ayez pas les mêmes adresses et que certaines zones mémoire (`vvar`, `vdso` ...) ne soient pas mappées aux mêmes endroits.
{: .prompt-warning }

- `global_str` est une variable globale constante, elle se retrouve donc dans la section `.rodata` (*Read Only Data*). Cette section sera dans une zone mémoire 🟣 qui ne sera accessible qu'en **lecture seule** lors de l'exécution du programme ;
- `var_globale_initialisee` est une variable globale initialisée, elle se retrouve donc dans la section `.data` qui, lors de l'exécution, se situera dans la zone mémoire 🟢 des données, accessibles en **lecture** et **écriture** ;
- `var_globale_non_initialisee` se trouve dans la section `.bss` qui ressemble fortement à `.data`, la seule différence est que toutes les variables dans `.bss` sont initialisées à `0` lors de l'exécution du programme. Une fois que l'initialisation est terminée, il n'y a plus de différences entre `.data` et `.bss` qui se retrouvent dans la zone mémoire 🟢 ;
- L'espace alloué pour stocker le prénom est dans le **tas** 🔵 (ou *heap*). Evidemment, on ne voit pas, lors de l'analyse statique, l'adresse de cet espace alloué car il est **alloué dynamiquement**, lors de l'exécution du programme ;
- La variable `prenom` est située dans la pile 🟡 car il s'agit d'une **variable locale**. Comme vous pouvez le constater, on sait que l'adresse du pointeur `prenom` est `rsp+18` mais on ne sait pas quelle est exactement cette adresse. De la même manière que le tas, la pile n'est allouée **qu'à partir de l'exécution** et n'est **pas localisée aux mêmes adresses** d'une exécution à une autre.

> Comme `prenom` est un pointeur, il pointe effectivement vers une adresse qui est dans le tas. Par contre, comme `prenom` est également une variable locale, il a aussi **sa propre adresse** dans la pile.
> 
> Bien sûr, il est toujours possible que certaines variables locales ne soient pas stockées dans la pile mais dans un registre par souci d'optimisation.
{: .prompt-warning }

Après avoir vu tout ça, cela nous rappelle qu'il y a, lors de l'exécution, des zones mémoires qui ont différents droits : `R`, `W` et/ou `X` pour respectivement la **lecture**, l'**écriture** et l'**exécution**.

Ce qui nous intéresse, finalement, c'est surtout ce qui se passe en mémoire lors de l'exécution. Pour rappel, notre but ultime est de contrôler `rip`. Il nous faut donc connaître notre marge de manœuvre en termes d'espace mémoire. 

> Mais là, on voit que la zone de code 🔴 où se promène `rip` est la seule qui soit **exécutable** parmi les autres. En plus elle est en lecture seule donc on ne peut même pas modifier le code pour faire ce que l'on veut : ça a l'air compliqué cette histoire 😞...
{: .prompt-info }

Effectivement, vu comme ça, on a l'impression d'être bloqués. Sauf que, ce cours permet justement de voir comment **contourner les protections** qui ont été mises en place au fur et à mesure pour sécuriser davantage les programmes.

Par exemple, voici **quelques pistes** que l'on pourrait utiliser :

- **l'adresse de retour** des fonctions se trouve dans la pile, si on arrive à la **modifier**, avec un dépassement de mémoire tampon (*buffer overflow*) par exemple, il sera possible de **faire pointer** `rip` n'importe où. Dans certains programmes très anciens, la pile était exécutable, on pouvait donc y mettre des instructions assembleur (un *shellcode*) et "**sauter**" dedans. Nous verrons comment faire dans le cas où la pile n'est pas exécutable ;
- il est possible de faire en sorte **d'allouer des zones mémoire** avec les droits `rwx` afin d'y mettre notre *shellcode* et y sauter ;
- il est possible d'utiliser à notre avantage les bibliothèques chargées avec notre programme comme la **libc** ;
- il existe bien **d'autres pistes** que nous verrons en détails en temps voulu 🫣.

> J'en vois déjà froncer des sourcils et se dire "mais je comprends rien à ce charabia 😵‍💫 !". Ne vous inquiétez pas, c'est normal. Il est important de passer du temps à comprendre en détails le **fonctionnement d'une méthode** d'exploitation avant de comprendre vraiment comment ça marche.
> 
> Il y a peut être certains termes qui vous paraissent flous comme "*buffer overflow*", "*shellcode*", "libc" etc., **nous les verrons ensemble**, ne vous inquiétez pas !
{: .prompt-tip }

## Analyse dynamique

Nous nous sommes échauffés en ouvrant notre programme dans un **décompilateur**, désormais voyons ce que nous pouvons tirer comme **informations** en le lançant dans un **débogueur**. 

Pour rappel, notre but ici est de **revoir quelques notions essentielles** dans le fonctionnement d'un processus mais aussi de commencer à mettre dans un coin de la tête de **potentielles méthodes** pour contrôler `rip` et réaliser une **exécution de code**. 

> Nous utiliserons **gdb** comme débogueur avec l'extension [pwndbg](https://github.com/pwndbg/pwndbg) qui est très pratique pour faire du *pwn* 👌. En revanche, nous changerons de variante de **gdb** une fois que l'on commencera l'exploitation dans le tas, dans un autre cours.
> 
> Vous pouvez évidemment utiliser l'extension **gdb** avec laquelle vous êtes le plus à l'aise (ex: gdb-gef, gdb-peda ...) mais certaines commandes ne seront pas présentes ni compatibles d'une extension à une autre.
> 
> Si vous souhaitez **toutes les installer rapidement** afin de pouvoir basculer rapidement d'une version à une autre, vous pouvez jeter un œil à la section `Installation de plusieurs versions de gdb` de l'annexe [Annexe n°2 : Gérer plusieurs versions de gdb et principales commandes pour déboguer le tas](/posts/exploitation_de_la_heap_partie_24).
{: .prompt-tip }

> Parmi les **prérequis** de cours, il y a le fait de **savoir utiliser un débogueur**. Si vous avez des lacunes ou que vous souhaitez vous rafraîchir la mémoire, n'hésitez pas à jeter un œil au chapitre de l'[analyse dynamique](https://reverse.zip/posts/introduction_au_reverse_partie_19/).
{: .prompt-tip }

Ouvrons le programme dans **gdb** avec `gdb ./exe` puis lançons le programme de telle sorte à ce qu'il s'arrête immédiatement dans la fonction `_start` avec la commande `starti`.

Voici où nous nous trouvons :

![](/assets/images/introduction_au_pwn/rip_starti.png)

> Nous n'allons **sûrement pas avoir les mêmes adresses** qui s'affichent dans `gdb` et c'est normal. En dehors du code de notre programme et des données qu'il utilise, le reste des sections mémoire est soumis à l'[ASLR](https://fr.wikipedia.org/wiki/Address_space_layout_randomization) (Address Space Layout Randomization).
{: .prompt-tip }

A ce stade, vous avez sans doute remarqué que `rip` n'est pas de la forme `0x401xxx`. En effet, pour l'instant nous **ne sommes pas** (encore) dans notre programme, plus précisément dans le code de notre programme.

> Il ne s'agit pas de la fonction `_start` de notre programme mais celle de `ld`. Chaque programme implémente **sa propre fonction** `_start`. Ne soyez pas étonnés de voir qu'il y a une fonction `_start` à l'adresse `0x7ffff7fe3290` et une autre à l'adresse `0x4010D0`.
{: .prompt-warning }

Utilisons la commande `libs` pour voir quels sont les différents *mapping* en mémoire :

![](/assets/images/introduction_au_pwn/libc_gdb_3.png)

> A partir d'un terminal bash, il est possible de lire le *mapping* mémoire d'un processus en lisant le fichier `/proc/PID/maps` si vous avez suffisamment de droits pour lire le fichier.
{: .prompt-tip }

A partir de là, on peut deviner dans quelles **sections mémoire** se situe `rip`. Oui ! A ce stade il se situe dans `ld`, vous savez, ce programme qui permet de réaliser la **phase d'initialisation**, dont le **chargement des bibliothèques** nécessaires. 

Egalement, on remarque qu'il y a des zones mémoire qui n'apparaissaient pas dans le décompilateur. En effet, il y a des zones mémoire qui ne sont chargées qu'au lancement du programme, nous ne pouvons pas les voir en analyse statique.

> Pour l'instant, ne nous focalisons pas sur `vvar`, `vdso` et `vsyscall`. Il s'agit de zones mémoire permettant **d'optimiser certaines interactions** (ex: des *syscalls* fréquemment utilisés comme `gettimeofday`) entre le *user land* et le *kernel land*.
> 
> On en reparlera si nécessaire 🙃.
{: .prompt-tip }

C'est pour ça qu'en *pwn* il ne faut pas **seulement** analyser le programme en **statique** car on peut passer à côté de pas mal de choses que l'on pourrait utiliser à notre avantage pour exploiter des programmes.

Autre remarque : on constate que `ld` est bien un **programme à part entière** au même titre que le notre. 

> Vous pouvez savoir quel est le chemin du *linker* `ld` en utilisant `ldd ./exe`. Cherchez le fichier à l'origine du lien symbolique de `/lib64/ld-linux-x86-64.so.2` (dans mon cas) et lancez `file` dessus pour vous en convaincre. Par exemple en lançant `file /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2` j'ai `ELF 64-bit LSB shared object, x86-64, version 1 (GNU/Linux), dynamically linked, BuildID[sha1]=4186944c50f8a32b47d74931e3f512b811813b64, stripped`.
> 
> Vous pouvez d'ailleurs l'exécuter, même s'il ne fera pas grand chose.
{: .prompt-tip }

Aussi bien `ld` que notre programme sont constitués principalement de **4 zones mémoire** :

1. une zone mémoire en **lecture seule** : il s'agit de l'entête ELF de notre programme. C'est ce que l'on voit, en partie, lorsque l'on fait `xxd exe | head` ;
2. une zone mémoire en **lecture** et **exécution** 🔴 : ce sont les instructions ( ou "code" ) de notre programme ;
3. une autre zone mémoire en **lecture seule** 🟣 : il s'agit de la zone des données en lecture seule (`.rodata` ...) ;
4. une zone mémoire en **lecture** et **écriture** 🟢 :  il s'agit de la zone des données modifiables (`.bss`, `.data` ...).

D'ailleurs, vous voyez que la pile (*stack*) **n'appartient pas seulement à notre programme**. Toutes les autres bibliothèques (`ld`, `libc` etc.) peuvent l'utiliser.

> La taille des zones mémoire est toujours un multiple d'une [page](https://fr.wikipedia.org/wiki/M%C3%A9moire_virtuelle#Taille_des_pages_pour_quelques_ordinateurs) de `0x1000` octets ce qui est bien plus que la **taille réelle** que prennent toutes les instructions de notre programme (~`0x250` octets). 
{: .prompt-tip }

Je vous épargne tous les détails de la phase d’initialisation de notre programme : mettons un point d'arrêt dans `main` avec `b main` et avançons jusque-là avec `c`.

Tout d'abord, voyons s'il y a du nouveau dans le *mapping* de la mémoire :

![](/assets/images/introduction_au_pwn/libs_map.png)

Parmi les changements, il y a :

- le chargement de **zones mémoires anonymes**;
- le chargement en mémoire de la **libc**.

Les zones mémoire dites "anonymes" sont des *mappings* créés avec `mmap` via l'option `MAP_ANONYMOUS`. Cela signifie que la zone mémoire sera initialisée avec des `0` contrairement aux autres zones mémoire que l'on vient de voir et qui sont mappées à partir de fichiers (plus précisément leur contenu).

Nous n'allons pas nous intéresser à ces *mappings* anonymes pour l'instant. Nous y reviendrons peut-être pour parler de [TLS](https://elixir.bootlin.com/glibc/glibc-2.38/source/sysdeps/x86_64/nptl/tls.h#L70) Thread-Local Storage (rien à voir avec le protocole de sécu' 😅 ) car cette zone mémoire contient des données qui peuvent nous être **bien utiles** dans certains cas 😏.

### La libc

#### Qu'est-ce que la libc ?

La **libc** est la bibliothèque standard du langage C. Elle fournit les **fonctionnalités de base** du système, comme la gestion des fichiers, l'allocation de mémoire, la gestion des processus et la communication, permettant aux programmes de C d'interagir avec le système d'exploitation **sans avoir à gérer directement** le matériel ou le noyau.

C'est cette bibliothèque qui implémente toutes les principales fonctions C que l'on utilise telles que `malloc`, `printf`, `execve`, `system` ...

Quand on parle de **libc** en *pwn*, il s'agit généralement d'un abus de langage. En effet, il n'y a pas "une" **libc** : il existe différentes implémentations de la **libc**, certaines sont orientées performances, taille restreinte, respect strict du standard ...

Sur votre distribution Linux, vous avez de grandes chances d'avoir la [glibc](https://fr.wikipedia.org/wiki/GNU_C_Library) (GNU C Library). Une autre implémentation très connue est la [musl libc](https://en.wikipedia.org/wiki/Musl) qui est conçue pour être **plus légère** et donc plus **adaptée pour de l'embarqué**.

> Comme pour `ld`, il est possible de trouver le chemin de la **libc** avec `ldd ./exe`. Vous pouvez même l'exécuter pour savoir quelle est la version de la **libc** utilisée.
{: .prompt-tip }

#### 🤝 Un ami pour la vie

![](/assets/images/introduction_au_pwn/bf.png)

> Je vois pas pourquoi on passe autant de temps à parler de la **libc**. Au final on a juste besoin de savoir qu'elle implémente la majorité des fonctions C, c'est tout 😒.
{: .prompt-info }

Eh bien détrompez-vous ! La **libc** a toute son importance en **pwn** ! Comme c'est elle qui implémente pratiquement toutes les fonctions C que l'on utilise tous les jours, elle va nous permettre, lorsque l'on arrive à contrôler `rip`, de **sauter dans les fonctions que l'on souhaite exécuter** et ce, même si notre programme ne les appelle pas à la base 😮.

Très souvent lorsque l'on fait du *pwn*, le but va être *in fine* d'ouvrir un *shell*, un terminal quoi. Il y a différentes manières d'y parvenir, les plus connues étant d'appeler `system("/bin/sh")` ou `execve("/bin/sh",NULL,NULL)`. Cela peut être réalisé sous 3 conditions :

1. on arrive à contrôler `rip` : on peut donc lui donner n'importe quelle valeur ;
2. on sait où se trouve la fonction à appeler (ex: `execve`, `system` ...) ;
3. on arrive à contrôler les premiers arguments (`rdi`, `rsi` et `rdx` en x64 ou sur la pile en x86).

Pour savoir à quelle adresse se trouve `system`, par exemple, on peut exécuter `p system` dans **gdb**. Cela retourne un résultat du style :

```
$1 = {int (const char *)} 0x7ffff7c50d70 <__libc_system>.
```

> Bon, énoncées comme cela, les **trois précédentes conditions** semblent être faciles à remplir. En réalité elles ne sont pas évidentes, et il y a souvent du boulot pour les satisfaire toutes ensemble.
> 
> C'est justement l'un des objectifs de ce cours : apprendre à avancer petit à petit à partir d'une vulnérabilité jusqu'à aboutir à un *shell*.
{: .prompt-tip }

Autre point à noter : c'est la **libc** qui est chargée d'exécuter la fonction `main` d'un programme. C'est d'ailleurs ce que l'on voit dans **gdb** dans la section "Backtrace" :

![](/assets/images/introduction_au_pwn/bt.png)

Pour résumer, voici comment on en est arrivé au `main` depuis le début :

![](/assets/images/introduction_au_pwn/global_worflow.png)

> En parlant de `malloc`, je ne vois pas où est la *heap* dans le mapping mémoire ?
{: .prompt-info }

A ce stade nous avons arrêté l'exécution à l'entrée de `main`. La *heap* n'a **pas encore été initialisée**. Allons directement à la fin du `main` avec la commande `fin`. Relançons `libs` et voyons ce que cela donne.

### La heap / le tas

Nous obtenons ceci :

![](/assets/images/introduction_au_pwn/heap_libs.png)

Le voilà en bleu ! Nous n'allons pas aller plus loin concernant le fonctionnement du tas car cela demande beaucoup de détails à tel point qu'il faille en faire tout un chapitre. Même un chapitre entier n'est pas suffisant pour y aborder toutes les techniques d'exploitation de la *heap* alors accrochez-vous 🤯 !

### La fin du processus

> Tu nous as pas dit comment le programme finit après avoir retourné de `main` ?
{: .prompt-info }

J'ai volontairement omis ce détail pour l'instant. La terminaison d'un processus n'est **pas très compliquée**, quelques fonctions sont appelées pour permettre au processus de quitter proprement.

Cela n'est pas très intéressant pour nous de savoir comment cela est fait exactement. Cela pourra nous être utile dans certains cas où nous pouvons réaliser une écriture arbitraire en mémoire : nous pourrons modifier certains pointeurs de fonctions appelées à la fin d'un processus (lorsque `exit` est appelée par exemple) afin d'exécuter des fonctions de notre choix (ex : `system`, `execve` etc.).

Nous en reparlerons beaucoup plus loin dans les chapitres liés au tas si je ne me trompe pas.

## 📋 Synthèse

- la condition *sine qua non* pour pouvoir exploiter une vulnérabilité en *pwn* est de **contrôler** `rip` ;
- il existe **différentes manières** d'y parvenir tout comme il existe **différentes vulnérabilités** exploitables ;
- nous avons revu rapidement la manière dont sont stockées en mémoire **les variables** dans un programme ;
- **l'analyse statique** à elle seule ne permet pas d'avoir un aperçu **exhaustif** de l'environnement d'exécution du programme : pas de pile, de tas, de bibliothèque ;
- nous avons vu comment est chargé un programme en mémoire dans les grandes lignes ;
- la **libc**, qui implémente les fonctions C standards, peut nous être très utile lors de la phase d'exploitation.