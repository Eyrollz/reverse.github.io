---
title: Partie 5 - Analyse statique  d'un mini-programme - introduction (1/5)
date: 2023-10-26 10:00:00
categories: [Reverse, Introduction au reverse]
tags: [x86, reverse, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# Analyse statique  d'un mini-programme : introduction (1/5)

Je vous propose de faire le *reverse* d'un programme assez simple afin que vous puissiez pratiquer et faire le lien avec les parties théoriques abordées.

Plus précisément, il s'agit d'une **analyse statique** du programme. Cela signifie que nous n'allons pas l'exécuter ni analyser son exécution dans un débogueur. De toute manière pour un programme aussi simple que celui que nous allons compiler, il n'y en a pas besoin 😅.

Nous allons passer **pas mal de temps**, lors des différentes étapes de *reverse*, afin de rentrer de plus en plus dans les détails et faire des liens entre programmation / assembleur etc. 

Veuillez donc m'excuser d'avance si le *reverse* de ce programme **s'étale sur plusieurs chapitre** mais il est primordiale, pour ne pas dire nécessaire, de passer pas mal de temps sur certaines notions de base en *reverse* 😇.

> Nous allons nous focaliser **exclusivement sur l'architecture x86** qui est celle qui est la plus utilisée sur les PC. C'est également l'une des plus simples même si cet avis est subjectif.
> 
> Le fait de se focaliser sur une architecture en particulier permet de moins se perdre dans les comparaisons et les différences qu'il peut y avoir.
{: .prompt-tip }

> Par abus de langage, on parle parfois de **x86** pour désigner de manière générale la version 32 bits (x86) ou 64 bits (x86_64).
{: .prompt-tip }

Comme cela a été dit auparavant, nous allons effectuer le *reverse* sous Linux car cela est bien plus simple.

## Notre premier programme à reverse

Voici le programme `main.c` codé en C que je vous propose d'analyser :

```cpp
int main()  
{  
 int a = 2;  
 int b = 3;  
  
 return a+b;  
}
```

Rien de bien méchant, on réalise une addition puis on retourne le résultat, le tout dans la fonction `main`.

Pour le compiler en 32 bits, vous pouvez utiliser la commande suivante `gcc -m32 -fno-pie main.c -o exe`.

> Si vous avez un soucis lors de la compilation en 32 bits, il suffit d'installer ce paquet `sudo apt-get install gcc-multilib`
{: .prompt-tip }

Quelques infos sur les **options de compilation** utilisées :
- `-m32` : permet de compiler en 32 bits
- `-fno-pie` : pour l'instant nous n'avons pas besoin de comprendre ce que cela fait exactement. Disons que cela nous simplifiera le *reverse*. Je vous expliquerai ce que cela fait en temps voulu 😉
- `-o` : destination du programme compilé. Vous pouvez modifier le nom si vous le souhaitez

> En fonction de la machine que vous utilisez et de la version de `gcc`, il se peut qu'il y ait **quelques différences** entre votre programme et celui du cours.
> 
> Il ne devrait pas y avoir énormément de différences dans les instructions mais il se peut que les **adresses** ne soient pas les mêmes.
> 
>  Toutefois, si vous souhaitez avoir la même version du programme que celle du cours, vous pouvez le télécharger ici : [mini_programme](https://drive.proton.me/urls/DZ4BYCKXGC#XhXkG4qgijmQ).
{: .prompt-warning }

> Mais pourquoi se forcer à compiler en 32 bits alors que l'on a tous des PC 64 bits de nos jours ? 🤔
{: .prompt-info }

En fait, la manière dont fonctionne un programme **x86** est légèrement différente de celle d'un programme **x86_64** (notamment dans la manière de gérer les arguments des fonctions, conventions d'appel ...). 

Il est donc ainsi intéressant de se focaliser dans un premier temps sur du **x86** puis voir les différences avec **x86_64**. D'ailleurs, les programmes 32 bits restent encore très utilisés.

Une grande partie des *malwares* est toujours développée en 32 bits, par exemple.

## Premières informations extraites

A ce stade nous avons un programme compilé nommé `exe`. Nous pouvons déjà utiliser la commande `file` pour avoir les informations élémentaires du programme `file exe` :
```
exe: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=d2b00fbb13a07b8a98dea2bc  
af274eae7072d113, for GNU/Linux 3.2.0, not stripped
```

- `ELF` ➡️ Le programme est un **ELF**, logique, nous sommes sous Linux
- `LSB` ➡️  *Least Significan Bit*. Il s'agit donc d'un programme ***Little Endian***
- `dynamically linked` ➡️  les bibliothèques utilisées sont **chargées dynamiquement**, à l'exécution, et ne sont donc pas présentes statiquement dans le programme
- `not stripped` ➡️  les **symboles** ne sont pas supprimés et sont encore présents dans le programme

> Les **symboles** sont des informations, principalement des chaînes de caractères, présentes dans un programme et sont notamment utilisées pour le déboguer. Elles ne sont pas pas nécessaires et peuvent être supprimées avec la commande `strip`.
> 
> Par exemple, les **noms de variables globales** et les **noms de fonctions** font partie des symboles.
{: .prompt-tip }

Nous pouvons également lancer le programme et afficher la valeur retourner avec `./exe ; echo $?`. Le résultat retourné est bien celui attendu : `5`.

## L'utilisation d'un désassembleur

Comme nous l'avions vu précédemment, il devrait y avoir un segment dans le programme qui contient le **code**, plus précisément les **opcodes**.

Néanmoins, ni vous, ni moi ne savons lire directement des opcodes comme ça 😅. Il va donc falloir utiliser un outil qui va partir du code "brute" et nous **transformer** ça en **instructions en assembleur**. On ne va tout de même pas le faire nous même à la main 🫣 !

Plusieurs outils existent :

- **objdump** : outil utilisable en ligne de commande inclus dans les GNU Binutils. Cet outil permet d'afficher les informations de base d'un programme ELF ainsi que de désassembler un programme.
- **radare2** : *framework* utilisable en ligne de commande permettant de réaliser une analyse statique sur un programme (désassemblage et décompilation) 
- **Cutter** : Version GUI de radare2
- **Ghidra** : Outil GUI développé par la NSA puis rendu *open source*. Il permet le désassemblage et la décompilation. Il peut être utilisé avec une multitude d'architectures.
- **Binary Ninja** : Outil GUI payant (mais dispose d'une version gratuite) plus récent que les autres qui propose le désassemblage et la décompilation.
- **IDA** : Outil GUI payant (mais qui dispose d'une version gratuite) qui propose le désassemblage, la décompilation et un *debugger* (qui n'est pas très ouf en soi 😶). Très utilisé dans le monde professionnel notamment pour de l'analyse de *malwares* ou recherche de vulnérabilités. Semble être moins utilisé pour d'autres architectures, notamment pour de l'embarqué / IoT.

**objdump** est pas mal pour faire une analyse rapide du code désassemblé dans le terminal sans prise de tête. Mais cela demeure tout de même un outil assez limité.

## Apprendre à utiliser IDA Freeware

Je vous propose d'apprendre à utiliser les fonctionnalités élémentaires d'IDA qui dispose d'une version *Freeware*.

> En temps normal j'aurais recommandé d'utiliser Ghidra pour débuter car IDA est un **logiciel payant et très cher**. Néanmoins, depuis quelques temps, ils proposent une **version gratuite** pour x86 et x86_64 avec un décompilateur dans le cloud.
> 
> De toute manière en *reverse*, on ne se limite pas à un outil en particulier mais il vaut mieux savoir passer d'un outil à un autre. Cela crée de la complémentarité et permet d'avoir une sorte de couteau suisse à disposition.
> 
> Evidemment nous n'aurons pas le temps d'utiliser chacun de ces outils mais on vous recommande vivement de toucher un peu à tout afin de vous familiariser avec ces outils incontournables.
{: .prompt-tip }

Vous pouvez télécharger une version gratuite pour x86/x86_64 [ici](https://hex-rays.com/ida-free/#download).

Une fois installé puis ouvert, ouvrez le programme `exe` que nous venons de compiler. Une fenêtre s'ouvre alors :

![](/assets/images/introduction_au_reverse/fst_ida.png)

Vous pouvez laisser les paramètres par défaut et cliquer sur "OK". Enfin l'interface d'IDA s'affiche.

![](/assets/images/introduction_au_reverse/Screens/ida.png)

Quelques infos sur les différentes fenêtres et onglets ouverts :

1. **IDA View** : C'est dans cette fenêtre que s'affichera le code désassemblé en mode "graphe" ou en mode "normal". Pour basculer de l'un vers l'autre appuyer sur `espace`.
2. **Functions** : liste des fonctions présentes dans le programme. Les fonctions commençant par `sub` sont celles qu'IDA renomme automatiquement car elles n'ont pas de nom ou leur symbole a été supprimé.
3. **Schéma du graphe** : affiche un schéma global du graphe du code désassemblé. En l'occurrence ce n'est pas très utile car notre fonction ne contient pas de sauts et est donc constituée d'un seul bloc.
4. **Output** : il s'agit d'une sorte de mini terminal qui affiche certains logs dont ceux qui proviennent des scripts IDA Python. Il y est également possible d'utiliser du code Python. Malheureusement ces deux fonctionnalités ne sont pas disponibles dans la version *Freeware*.
5. **Hex View** : cet onglet permet de regarder le contenu brut d'une zone du programme. Elle ne contient donc que des données hexadécimale. Elle peut être utile lorsque l'on souhaite réaliser des modification (que l'on appelle *patchs*) dans le programme.
6. **Structures** : cet onglet contient certaines structures du base ainsi que des structures que vous aimeriez utiliser après les avoir ajoutées. Généralement, lorsque l'on réalise le *reverse* d'un programme, il n'y a plus les informations concernant les structures, c'est donc à nous de "deviner" le format de ladite structure. Une fois que l'on a trouvé globalement sa forme et sa taille, nous pouvons la créer via cet onglet.
7. **Enums** : cet onglet permet de définir vos propres énumérations.
8. **Imports** : il s'agit de la liste de toutes les fonctions importées par un programme. Cela est pratique pour avoir une idée de ce que fait le programme : est-ce qu'il utilise des fonctions réseau ? de cryptographie ? Evidemment les programmes les mieux protégés n'ont que très peu de fonctions importées au départ et préfèrent les importer de manière dynamique (par exemple avec une table de hachage).
9. **Exports** : cet onglet est surtout utile pour les programmes de type "bibliothèque" (`.a` ou `.so` sous Linux, `.dll` sous Windows) qui contiennent les fonctions qu'elles rendent accessibles à tout autre programme qui utiliserait la bibliothèque en question.

Le mode graphe est vraiment pas mal car il permet d'avoir un aperçu du flux de contrôle (c'est-à-dire le lien entre les différents blocs d'instructions) et voir si la fonction s'exécute plutôt de manière linéaire ou s'il y a des boucles, un "switch" ...

Avant d'aller plus loin, je vous invite à prendre l'habitude de faire quelques réglages dont on a souvent besoin lorsque l'on travaille avec IDA. Allez dans `Options`➡️`General`. Dans la fenêtre qui s'ouvre cochez la case suivante et saisissez la valeur suivante :

![](/assets/images/introduction_au_reverse/Pasted image 20231025103733.png)

Cela permet d'afficher les adresses des instructions et d'afficher leur opcode.

> L'affichage des opcodes n'est pas si important que ça, si cela vous dérange visuellement vous pouvez la désactivez en saisissant `0` dans la case idoine.
{: .prompt-tip }

## Analyse de la fonction `main`

Comme vous pouvez le constater dans l'onglet `Functions`, il y a plus d'une dizaine de fonctions alors que dans notre programme ... on n'en avait défini qu'une !

On nous as toujours dit que la fonction `main` d'un programme était la première à être appelée. Sauf que ce n'est pas exactement ça. En fait, c'est la fonction `start` qui appelée en premier. Ensuite, c'est la [fonction](https://refspecs.linuxbase.org/LSB_3.1.1/LSB-Core-generic/LSB-Core-generic/baselib---libc-start-main-.html) `__libc_start_main` de la bibliothèque standard **libc** qui est exécutée afin qu'elle appelle le `main` en lui fournissant les bons arguments `argv` et `argc`.

> La **libc** est la bibliothèque standard du C sous Linux, son équivalent sous Windows est **msvcrt.dll**.
> 
> Cette bibliothèque contient les **fonctions de base en C** que vous avez sûrement utilisées moult fois telles que : `printf`, `puts`, `scanf`, `malloc`, `free`, `strcpy` ...
{: .prompt-tip }

Je vous propose d'utiliser [Compiler Explorer](https://godbolt.org/) afin d'avoir le lien entre la fonction `main` et son code assembleur. 

> Vous pouvez utiliser la version `x86-64 gcc 13.2` de gcc en n'oubliant pas d'utiliser l'option `-m32` pour compiler en 32 bits.
{: .prompt-tip }

On obtient alors le même code assembleur que celui qui est affiché par IDA (à quelques notations près) :

![](/assets/images/introduction_au_reverse/disasm.png)

Quelques explications :

Les zones **1** et **5** correspondent respectivement à ce que l'on appelle **prologue** et **épilogue** d'une fonction. Nous n'allons pas nous y attarder pour l'instant, nous nous y intéresserons un peu plus tard.

Les zones **2** et **3** correspondent à l'initialisation des variables `a` et `b`. 

La zone **4** correspond à l'addition `a+b`.

Finalement ce qui est réellement nouveau pour nous est cette histoire de prologue et épilogue. Aussi, je ne vous ai toujours pas dit ce que faisait chacune de ces instructions. Patience, tout vient à point à qui sait attendre 😇.

Avant d'aller plus loin il est nécessaire de comprendre deux notions essentielles : les **registres** et la **pile**.