---
title: Partie 21 - L'analyse dynamique - analyser les registres et la mémoire (3/4)
date: 2023-10-10 10:00:00
categories: [Reverse, Introduction au reverse]
tags: [x86, reverse, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# L'analyse dynamique : 📖 analyser les registres et la mémoire (3/4)

Désormais, nous savons comment avancer dans gdb que ce soit **pas à pas** ou plus **rapidement**.

Un autre point fort des **débogueurs** est qu'ils ont **accès à la mémoire** du processus débogué. Vous l'aurez compris, il existe donc des moyens d'**afficher** des zones mémoire.

Mais il va falloir faire attention à plusieurs choses :

- comment afficher une zone mémoire ? en hexadécimal ? en *string* ? en décimal ?
- comment afficher les données en mémoire ? octet par octet ? par groupe de 4 octets ? 

Nous verrons comment faire pour gérer tout cela.

## 📄 Afficher une valeur

Commençons par la commande la plus simple pour afficher une valeur : `print`.

> **Astuce gdb** : La commande `p` (ou `print`) permet d'afficher une valeur quelconque ou la valeur d'une registre.
> 
> Si la valeur à afficher est une adresse (ou pointeur), elle ne sera pas déréférencée.
{: .prompt-tip }

Pour comprendre comment fonctionne `print`, chargeons le programme dans gdb et mettons un unique point d'arrêt dans la fonction `calcul`. Lançons l'exécution, elle s'arrêtera ici :

![](/assets/images/introduction_au_reverse/stop_run_bp.png)

### Afficher un registre

Première chose que l'on peut faire est d'afficher les arguments de la fonction. Comme nous sommes en 64 bits, ils sont stockés dans `rdi`,`rsi` et `rdx`.

> Mais on les voit déjà dans l'interface 🤨 !
{: .prompt-info }

C'est vrai qu'ici ce n'est pas ce qu'il y a de plus utile. Par contre, on observe dans le code assembleur que ce sont plus précisément les registres `edi`,`esi` et `edx` qui sont utilisés. Essayons d'afficher leur contenu même si on peut le deviner à partir de l'interface.

> **Astuce gdb** : Pour afficher un registre, il suffit de le préfixer avec le signe `$`. Exemple : `print $reg`.
{: .prompt-tip }

On a alors :

```sh
pwndbg> p $edi  
$1 = 1  
pwndbg> p $esi  
$2 = 2  
pwndbg> p $edx  
$3 = 3
```

> Vous remarquerez que gdb stocke les résultats affichés dans des variables du type `$1`, `$2` etc. qui pourront être affichées à leur tour en faisant, par exemple, `p $1`.
{: .prompt-tip }

Ce qui est pas mal est que l'on n'est pas limités aux registres affichés dans l'interface. On peut également afficher les registres de taille inférieure (ou sous-registres) comme `ax`, `al`, `ah` ...

### Afficher un symbole

Lorsqu'un programme n'est pas *strippé* ou que, tout simplement, il fait appel à des fonctions externes, il est possible d'afficher leur adresse avec `print`.

Grâce à `pwndbg`, nous pouvons même afficher les adresses des fonctions de la libc que l'on a pas appelées dans notre programme.

> Mais ça sert à quoi d'afficher leur adresse si on ne les appelle pas ? 🙄
{: .prompt-info }

Eh bien quand on fait de **l'exploitation de binaire** (ou *pwn*), on veut faire en sorte que le programme saute à n'importe qu'elle adresse. Ainsi, en le faisant sauter sur `execve`, par exemple, il est possible d'ouvrir un *shell* sur la machine de la victime 😈.

Pour afficher l'adresse d'une fonction dont le symbole est présent dans le programme, il suffit de faire `print fonction`. Par exemple :

![](/assets/images/introduction_au_reverse/main_execve.png)

> La fonction `main` et `execve` ont des adresses très éloignées car elle ne sont pas chargées au même endroit dans la mémoire.
{: .prompt-tip }

Il est également possible d'afficher le contenu (instructions assembleur) d'une fonction.

> **Astuce gdb** : La commande `disass fun` (ou `disassemble`) permet d'afficher les instructions de la fonction `fun`.
{: .prompt-tip }

Exemple :

![](/assets/images/introduction_au_reverse/disass.png)

En ce qui concerne les **variable globales**, je vous propose de compiler le code suivant et de l'ouvrir dans gdb :

```cpp
int var_a = 5;  
unsigned long long var_b = 213;  
  
int main()  
{  
 return 1;  
}
```

Pour afficher le contenu de `var_a` nous pouvons faire :
```sh
pwndbg> p var_a  
'var_a' has unknown type; cast it to its declared type
```

On remarque que gdb a besoin de savoir quel est **le type** de la variable à afficher ( ou vers quel type la **convertir**). Essayons de la sorte :

![](/assets/images/introduction_au_reverse/casts.png)

Finalement ce que veut principalement connaître gdb est :

- la **taille** de la variable
- si elle est **signée ou non**

En renseignant le type nous pouvons fournir ces **deux informations**.

### Afficher une valeur immédiate

Via `print` nous pouvons afficher des valeurs immédiates, par exemple : 

```sh
pwndbg> p 1234  
$4 = 1234
```

![](/assets/images/introduction_au_reverse/quelle_indignite.png)

Bon j'avoue que comme ça, ça a l'air éclaté car cela ne fait rien à part afficher la valeur ... qui est déjà affichée.

Pourtant, cela a notamment deux grandes utilités :
1. afficher **le résultat d'un calcul**
2. afficher une valeur dans **différents systèmes de numération** 

En effet, parfois, on n'a pas envie, ou on a la flemme, de faire un calcul de tête notamment lorsqu'il y a de l'hexadécimal en jeu. Exemple :

```sh
pwndbg> p/x 0x123 * 100 -2  
$8 = 0x71aa
```

> Ici `/x` est un format permettant d'afficher des données en hexadécimal comme on le ferait en C avec `printf("0x%x",0x123*100-2);`. 
{: .prompt-tip }

Ça tombe bien, voyons les formats !

### Les formats

Une fonctionnalité très utile lorsque souhaite afficher des données est **les formats**.

Cela permet de basculer d'un **système de numération** à un autre, d'afficher le caractère correspondant à un nombre en ASCII ...

- **o** : octal
- **x** : hexadécimal
- **u** : décimal non signé
- **t** : binaire
- **f** : nombre à virgule (ou flottant)
- **a** : adresse
- **c** : char
- **s** : chaîne de caractères

Quelques exemples :

```sh
pwndbg> p/x 195948557  
$1 = 0xbadf00d  
pwndbg> p/d 0xbadf00d  
$2 = 195948557  
pwndbg> p/c 0x48  
$3 = 72 'H'
pwndbg> p/t 0x5  
$4 = 101
```

> Si vous souhaitez connaître plus de fonctionnalités concernant la commande `print`, vous pouvez vous rendre sur cette [page de manuel](https://visualgdb.com/gdbreference/commands/print). 
{: .prompt-tip }

## 🔎 Examiner la mémoire

Nous avons vu les différentes manières d'utiliser `print` afin d'afficher des valeurs. Comme cela a été mentionné précédemment, `print` ne **déréférence pas** l'argument qu'on lui donne, il se contente que de l'afficher ou d'afficher son contenu s'il s'agit d'une **variable** ou d'un **registre**. 

Or, comme vous l'avez sans doute remarqué, de nombreux registres pointent vers des zones mémoire. Ainsi, on aimerait bien, au lieu d'afficher l'adresse pointée, **afficher le contenu** présent à cette adresse. Cela implique donc que l'adresse utilisée soit **déréférencée**.

> Quand on analyse une adresse, il faut s'assurer qu'elle est valide et qu'elle pointe bien vers une zone mémoire accessible sinon gdb va râler 😠.
{: .prompt-warning }

Voyons donc comment s'en servir.

> **Astuce gdb** : Vous pouvez utiliser le raccourcis `x` ( pour `explore`) afin d'examiner le contenu d'une zone mémoire.
{: .prompt-tip }

> Ne pas confondre la commande `x` avec le format `/x`.
{: .prompt-warning }

Tout d'abord, il faut savoir que `x` accepte également un format pour afficher le résultat. En guise d'exemple, reprenons notre petit programme qui réalise plusieurs appels à `calcul` et arrêtons nous à la première instruction du `main`.

Comme nous sommes en **64 bits**, les deux premiers arguments `int argc` et `char **argv` sont respectivement stockés dans `rdi` et `rsi`.

Pour ce qui est de `rdi`, comme `argc` n'est pas un pointeur, si on tente de l'examiner, gdb va râler :

```sh
pwndbg> x/x $rdi  
0x1:    Cannot access memory at address 0x1
```

Maintenant examinons le contenu de `rsi` :

```sh
pwndbg> x/x $rsi  
0x7fffffffddd8: 0xffffe15c
```

Le contenu de `rsi` (dans mon cas) est bien `0x7fffffffddd8` qui pointe vers `0x7fffffffe15c`. Mais comme vous pouvez le constater, gdb n'a affiché que **les 4 octets** de poids faible au lieu d'afficher les 8. 

Pas de soucis ! Nous allons pouvoir y remédier en spécifiant la taille du résultat.

### 🔢 L'usage de différentes taille

J'ai une **bonne** et une **mauvaise** nouvelle.

🟢 La **bonne nouvelle** est que si vous vous souvenez du chapitre des tailles de données (`byte`, `word`, `dword`, `qword` ...) vous allez pouvoir comprendre cette partie assez vite.

🔴 La **mauvaise nouvelle** est que gdb utilise des tailles qui ne sont pas en adéquations avec celles que l'on a vues et qui sont utilisés par IDA, Ghidra, objdump ...

Voici les **tailles** définies dans gdb :

| Abréviation | Signification | Taille (en octets) |
|-------------|---------------|--------------------|
| `b`           | *byte*          | 1                  |
| `h`           | *half word*     | 2                  |
| `w`           | *word*          | 4                  |
| `g`           | *giant word*    | 8                  |

Pour ne pas se tromper avec la manière dont sont appelées les tailles de données, il suffit de se rappeler de ceci :

- Pour **gdb** : un word = 4️⃣ octets
- Pour **les autres** : un word = 2️⃣ octets

Reprenons le précédent exemple pour afficher l'adresse pointée par `rsi` :

```sh
pwndbg> x/xg $rsi    
0x7fffffffddd8: 0x00007fffffffe15c
```

Voilà !

> **Astuce gdb** : Vous pouvez spécifier un nombre d'éléments à afficher avant les formats afin d'afficher plus ou moins de données en mémoire. 
{: .prompt-tip }

> Le **nombre d'éléments** à afficher ainsi que **la taille** ne sont utilisables qu'avec `x`. Cela ne **fonctionnera pas** avec `print` où seuls les formats (décimal, binaire, hexadécimal ...) sont utilisables.
{: .prompt-warning }

Pour afficher les 8 éléments après `0x7fffffffddd8` nous pouvons faire ceci :

```sh
pwndbg> x/8xg $rsi    
0x7fffffffddd8: 0x00007fffffffe15c      0x0000000000000000  
0x7fffffffdde8: 0x00007fffffffe1a8      0x00007fffffffe1b7  
0x7fffffffddf8: 0x00007fffffffe1cb      0x00007fffffffe201  
0x7fffffffde08: 0x00007fffffffe218      0x00007fffffffe223
```

La première ligne contient l'adresse de `argv[0]` qui pointe vers le chemin du programme :

```sh
pwndbg> x/s 0x00007fffffffe15c  
0x7fffffffe15c: "/home/(...)/exe"
```

Pour rappel, comme nous sommes en *little endian*, voici comment sont **agencées** les adresses mémoire dans ce qui est affiché :

![](/assets/images/introduction_au_reverse/gdb_mem.png)

Il est important de bien comprendre cet agencement car, certes, au début ce n'est pas évident de se représenter ce vers quoi chaque adresse pointe. Toutefois, en prenant le temps d'assimiler cette disposition, c'est du **temps de gagné** par la suite lorsque vous voudrez modifier une zone mémoire. En effet, il faudra savoir exactement l'adresse à utiliser pour ne pas modifier la mémoire qui est autour.

Autre **point important**, si vous afficher une zone mémoire **en octets**, le **boutisme n'a plus de sens** auquel cas les données se lisent de gauche à droite :

![](/assets/images/introduction_au_reverse/gdb_mem_bytes.png)

> **Astuce gdb** : Avec `x`, vous pouvez également donner en argument une expression avec des opérations (addition, soustraction, multiplication ...).
> 
> Cela peut être pratique pour afficher une donnée dans un tableau dont on connait l'index et l'adresse de base. Par exemple, pour afficher la 5ème case d'un tableau d'éléments de 64 bits : `x 0x401000+8*5` (en supposant que le tableau soit stocké à partir de l'adresse `0x401000`).
{: .prompt-tip }

### 👀 Examiner la pile

La commande `x` est très utile notamment pour afficher un certain **nombre d’éléments** sur la pile. Ainsi, si on souhaite afficher les 10 premiers éléments de la pile, nous pouvons faire :

- En **x86** : `x/10xw $esp`
- En **x86_64** : `x/10xg $rsp`

Pour mieux illustrer mes propos et comprendre comment va être affichée la pile dans gdb, compilons notre programme en 32 bits. Ensuite, mettons un point d'arrêt dans la fonction `calcul` (**après le prologue**) et lançons l'exécution. Le programme s'arrête lors du premier appel qui `calcul(1,2,3);`

Affichons maintenant les 5 premières valeurs de la pile. Vous devriez avoir un affichage semblable à ceci (avec des adresses différentes sans doute) :

![](/assets/images/introduction_au_reverse/stack_gdb.png)

Faisons un peu de gymnastique d'esprit pour comprendre comment est **agencée la pile** dans l'affichage. En effet, depuis le début on représente la pile comme un tableau vertical d'éléments mais là, va falloir nous adapter et nous habituer à cet affichage.

Alors, vous arrivez à vous y retrouver ? Bon. Voyons cela de plus près ensemble :

![](/assets/images/introduction_au_reverse/gdb_pile_details.png)

Comme le fait d'afficher la pile est quelque chose de très récurrent quand on fait de l'analyse dynamique, autant comprendre comment interpréter l'affichage de gdb, ça mange pas de pain  🥖 !

> Parfois, lorsque la *stack frame* est très grande, que l'on peut pas l'afficher en entier dans gdb et que l'on désire afficher les dernières valeurs de la pile, il est possible d'utiliser plutôt le registre`ebp`/`rbp` afin de n'afficher que ce qui nous intéresse.
> 
> Par exemple, si on souhaite afficher seulement les 3 dernières valeurs de la pile, nous pouvons faire `x/3xw $ebp-4*3` (car un élément de la pile fait 4 octets en x86).
{: .prompt-tip }

## 🔦 Chercher des données en mémoire

Après avoir analysé le programme statiquement, nous pouvons trouver des chaînes de caractères ou simplement des valeurs qui semblent être importantes. 

Imaginons qu'en analysant un *crackme* on voit que le *flag* est généré dans un fonction assez compliqué mais qu'ensuite il est inséré en mémoire sous la forme `flag{XXXXXXXXXXXX}`. Il pourrait alors être intéressant de savoir comment chercher des chaînes de caractères en mémoire.

> **Astuce gdb** : La commande `search` de pwndbg permet de rechercher des motifs en mémoire.
{: .prompt-tip }

En l'occurrence, nous pourrions faire ceci :

![](/assets/images/introduction_au_reverse/search_pwndbg.png)

Ensuite c'est à nous de filtrer le résultat afin d'éliminer les faux positifs.

Si vous souhaitez chercher des valeurs et non pas seulement des chaînes de caractères, je vous renvoie vers la [documentation](https://browserpwndbg.readthedocs.io/en/docs/commands/procinfo/search/) de la commande `search` afin d'y voir les différentes options disponibles.

## 📋 Synthèse

Voilà ! Vous savez désormais comment lire des données en mémoire 😎 !

Evidemment, rien de tel qu'un peu d'entraînement afin de se familiariser avec les notions vues lors de ce chapitre :

- Avec `p` on **affiche une valeur** ou le contenu d'un registre ou d'une variable.
- Avec `x` on peut l'**examiner**, c'est-à-dire la déréférencer afin d'afficher la valeur pointée.
- Il est possible **d'afficher la valeur des registres** en les préfixant avec `$`. De plus, les **sous-registres** d'un registre sont utilisables.
- Lorsque des **symboles** (fonctions, variables ...) sont présents, il est possible de les afficher afin d'avoir quelques informations.
- Différents **formats** sont utilisables afin de choisir le système de numération à utiliser pour afficher le résultat.
- Il est possible de **regrouper des données** par groupes d'octets en spécifiant une taille. Cependant, le `word` pour gdb est de **4 octets** bien que d'habitude il soit de 2.
- En spécifiant un nombre avant le format et la taille des données, on choisit le nombre d’éléments à afficher lorsque l'on examine la mémoire.
- La commande `x` permet, entre autre, d'afficher les premiers éléments de la pile.
- La commande `search` permet de **chercher un motif** en mémoire




