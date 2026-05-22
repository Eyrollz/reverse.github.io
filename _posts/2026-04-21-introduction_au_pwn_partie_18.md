---
title: Partie 18 - Exploiter les format strings - bonus (4/5)
date: 2026-04-21 10:00:00
categories: [Pwn, Introduction au pwn]
tags: [x86, pwn, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# Exploiter les *format strings* : bonus (4/5)

## ✨ Quelques bonus ✨ 

### 1️⃣ Bonus n°1 : Copier le contenu d'un index vers une adresse pointée depuis un autre index

Il existe une astuce qui peut être utile lorsque l'on souhaite copier directement une valeur intéressante en mémoire vers une adresse pointée par un pointeur. 

Comme le titre n'est pas très explicite, voici un exemple pour comprendre de quoi il s'agit :

![](/assets/images/introduction_au_pwn/copie_idx_fmt.png)
1. `addr` est un pointeur situé sur la pile à **l'index n°4** qui **pointe vers une valeur quelconque** ;
2. nous souhaitons modifier cette valeur pointée par **le contenu de l'index n°2**, à savoir `0xaabbccdd` ;
3. une fois cette copie réalisée, **la valeur pointée par** `addr` **sera** `0xaabbccdd`.

Pour que l'utilité de cette astuce soit encore plus claire, utilisons le programme suivant :

```cpp
#include <stdio.h>
#include <stdlib.h>

// Compilation : gcc -g -m32  main.c -o exe

void bravo()
{
    puts("Bravo !");
    exit(213);
}

void echec()
{
    puts("Echec ...");
    exit(1);
}

int main() 
{
    char buffer[0x100]= {0};
    
    void *addr_bravo = bravo;
    void *addr_echec = echec;
    
    void (**func_ptr)(void) = malloc(sizeof(*func_ptr));
    *func_ptr = addr_echec;
    
    // Lecture et affichage de la FMT
    fgets(buffer,sizeof(buffer), stdin);
    printf(buffer);
    
    // Appeler la fonction pointee
    (*func_ptr)();
    
    return 0;
}
```

Accès au conteneur Docker :

- ⬇️ **Téléchargement** : [pwn-fmt-exo-bonus-1.zip](https://drive.proton.me/urls/VWF04GRSY8#3tgpvrfgtl2m)
- 🔎 **SHA256 & Analyse Virus Total** : [e9af5077d6cebf7fda1f42068d7bcd94d452ce23b9c530bb5458d09f151af29e](https://www.virustotal.com/gui/file/e9af5077d6cebf7fda1f42068d7bcd94d452ce23b9c530bb5458d09f151af29e)
- ⚙️ **Construction et lancement du conteneur** :

```sh
docker build -t pwn-fmt-exo-bonus-1 .

docker run -it --rm -p 1234:1234 --cap-add=SYS_PTRACE --security-opt seccomp=unconfined pwn-fmt-exo-bonus-1
```

Le programme est écrit d'une manière assez bizarre, je vous l'accorde. Il lit puis affiche une chaîne de format avant d'exécuter la fonction pointée par `func_ptr` qui devrait, normalement 🙄, toujours être `echec`.

Pas besoin de s'étendre davantage, vous avez compris notre mission : **faire en sorte que la fonction** `bravo`**soit appelée**.

Une fois le programme compilé, il est possible d'investiguer les adresses suivantes dans **gdb** :
```
$ ./exe

%p-%p-%p-%p-%p-%p-%p
0x100-0xf3e025c0-0x58cc5257-0x58cc51dd-0x58cc520e-0x58de61a0-0x252d7025
Echec ...
```

Vous pouvez également ajouter des appels à `printf`afin de voir à quel index est situé chaque variable / pointeur. Nous constatons la présence des valeurs suivantes :

- index **n°4** ➡️ adresse de la fonction `bravo` ;
- index **n°5** ➡️ adresse de la fonction `echec` ;
- index **n°6** ➡️ mémoire dynamiquement allouée qui contient l'adresse de la fonction à appeler.

Nous avons besoin **d'écrire (ou copier)** la valeur située à **l'index n°4** à l'adresse pointée par **l'index n°6** :

![](/assets/images/introduction_au_pwn/copie_addr_bravo.png)

Le programme étant **PIE** et n'ayant droit qu'à **une tentative**, nous ne pouvons pas utiliser de fuite mémoire dans un premier temps avant de tenter de modifier le contenu du pointeur de fonction.

C'est à ce moment qu'entre en jeu une **astuce peu connue** du grand public : **l'usage de l'astérisque** dans une chaîne de format.

#### L'utilisation de l'astérisque `*`

Pour comprendre comment fonctionne l'utilisation de l'astérisque, examinons un exemple concret basé sur le précédent programme :

```
$ echo '%.*1$x' | ./exe

0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100
Echec ...
```

Une chose est sûre, la chaîne de format fait mal aux yeux. Et encore, vous n'avez rien vu 🤭. 

Nous connaissons le fonctionnement de `%1$x`, cela affiche la première valeur en hexadécimal. En ajoutant `.*`, cela permet toujours d'afficher la première valeur en hexadécimal tout en utilisant une largeur de champ égale au premier index, c'est-à-dire `0x100`. C'est pourquoi nous voyons plein de caractères `0`utilisés. C'est comme si l'on avait utilisé `%1$.256p`.

En réalité, ce qui nous intéresse avec cette astuce **n'est pas la valeur affichée** *in fine* mais plutôt **le nombre de caractères** qui seront affichés au final. En l'occurrence `256`.

De même qu'en utilisant `%.*1$x` nous pouvons afficher `0x100` caractères, en utilisant `%.*4$x` nous pouvons écrire ... Je ne sais pas exactement combien de caractères, mais un nombre égal à la **valeur de l'adresse** de la fonction `bravo`.

#### Passons à l'action

En combinant cela avec `%6$n` nous pouvons, très simplement, écrire **l'adresse de la fonction** `bravo`(index n°4) **dans le pointeur de fonction** `func_ptr`(index n°6) :

```
$ echo -e '%.*4$x%6$n' | ./exe > /dev/null
$ echo "Resultat : $?"
Resultat : 213
```

> La sortie standard est redirigée vers `/dev/null` afin d'éviter d'afficher des gigas octets de caractères.
{: .prompt-tip }

Pour savoir quelle fonction a été appelée, nous pouvons nous référer au **code de retour** du programme. Ici, il vaut `213`, c'est donc bien la fonction `bravo`qui a été appelée !

#### Détails de la chaîne de format

Peut-être que des **explications supplémentaires** ne feraient pas de mal à certains 😉.

Décortiquons la chaîne de format `%.*4$x%6$n` :

- `%.*4$x` : affiche autant de caractères que la **valeur à l'index n°4**. Par exemple : `0x58cc51dd == 1489785309`. Nous pourrions, de manière équivalente, remplacer `%.*4$x` par `%.1489785309x`. Evidemment, comme nous ne connaissons pas à l'avance l'adresse de la fonction `bravo`, l'avantage d'utiliser `%.*4$x` est de **ne pas avoir à prendre en compte l'ASLR** ;
- `%6$n` : écrit le nombre de caractère affichés (en l'occurrence, l'adresse de la fonction `bravo`) **à l'adresse pointée par le 6ème index** qui n'est autre que le **pointeur de fonction** `func_ptr`.

#### Aller plus loin : choisir l'index de la largeur de champ à utiliser

Et si on poussait le bouchon encore un peu plus loin ?

`%.*4$x` permet d'afficher autant de caractères que la valeur présente à l'index n°4. Mais saviez-vous qu'il est **même possible de choisir l'index de la largeur de champ** (le sorte de *padding* quoi) à utiliser ?

Par exemple, avec `%4$*1$x` le programme va :

- **afficher** la valeur située à **l'index n°4** en hexadécimal, c'est donc le **paramètre positionnel**;
- utiliser une **largeur de champ** égale à la valeur stockée à **l'index n°1**.

> Euh ... tu as inversés les index non 🧐 ?
{: .prompt-info }

Ce qui est pénible avec cette écriture est que l'on ne sait plus qui est quoi. Une astuce très simple pour se rappeler de ce à quoi correspond chaque index est :

- l'index le **plus à gauche** est le **paramètre positionnel** ;
- l'index (ou la valeur) le **plus à droite** est lié à la **largeur de champ**.

Pour mieux comprendre, voici l'équivalent de `%.*4$x` en utilisant **une largeur de champ "classique"** :

![](/assets/images/introduction_au_pwn/equivalence_asterisque.png)

Bon, n'entrons pas plus dans les détails, je sais que ça fait beaucoup chauffer les neurones ces choses 🤯. Au moins, vous savez désormais que ça existe et comment ça marche.

#### Résumé de l'usage de l'astérisque

Pour résumer, cette astuce est très utile :

- pour **copier une valeur** d'un index vers une adresse pointée depuis la pile ;
- **afficher un grand nombre de caractères** en utilisant un nombre limité de caractères dans la chaîne de format.

> Si vous vous demandez d'où vient **l'usage de l'astérisque** dans les chaînes de format en C, voici quelques éléments de réponse ci-dessous.
> 
> Certains programmes l'utilisent de la sorte : `printf("Affichage : %.*s\n", N, buffer);`.
> 
> Cela permet d'afficher au maximum `N` octets contenus dans `buffer`. Cela est très utile pour **limiter le nombre d'octets affichés** notamment lorsque le *buffer* utilisé ne contient pas une chaîne de caractères **terminée par un octet nul**.
{: .prompt-tip }

### 2️⃣ Bonus n°2 : Le module `fmtstr` de pwntools

Si vous êtes du genre à vouloir automatiser les choses, lorsque c'est possible, n'hésitez pas à jeter un œil au module [fmtstr](https://docs.pwntools.com/en/stable/fmtstr.html) de **pwntools** qui facilite l'exploitation de chaîne de format vulnérables.

### 3️⃣ Bonus n°3 : Sauvegarde de la pile

Lorsque l'on utilise un **paramètre positionnel** (ex : `%213$x`), le programme va **copier la pile** et **utiliser cette copie** pour toutes les opérations ultérieures (ex : afficher une valeur dans un format donné, écrire une valeur en mémoire avec `%n`).

Analysons ce que cela signifie à travers le programme suivant:

```cpp
#include "stdio.h"

//  gcc -g -m32 main.c -o exe -Wno-int-conversion

int main()
{
    char buffer[0x100]= {0};
    volatile int stack_var = 0xdeadbeef;
    volatile unsigned int stack_addr = &stack_var;

    printf("stack_var (avant) : %p\n",stack_var);
    printf("stack_addr : %p\n",stack_addr);

    // Lecture et affichage de la FMT
    fgets(buffer,sizeof(buffer), stdin);
    printf(buffer);

    printf("stack_var (apres) : %p\n",stack_var);

    return 0;
}
```

Accès au conteneur Docker :

- ⬇️ **Téléchargement** : [pwn-fmt-exo-bonus-2.zip](https://drive.proton.me/urls/R2P5BR3EJW#qT9AHHa3lhfG)
- 🔎 **SHA256 & Analyse Virus Total** : [fc8e84f64c27f5a778fb492eddb4cead317283fd6598c71eb037077624da569d](https://www.virustotal.com/gui/file/fc8e84f64c27f5a778fb492eddb4cead317283fd6598c71eb037077624da569d)
- ⚙️ **Construction et lancement du conteneur** :

```sh
docker build -t pwn-fmt-exo-bonus-2 .

docker run -it --rm -p 1234:1234 --cap-add=SYS_PTRACE --security-opt seccomp=unconfined pwn-fmt-exo-bonus-2
```

Tentons de modifier la valeur de `stack_var`de deux manières :

- **en utilisant** un paramètre positionnel ;
- **sans utiliser** de paramètre positionnel.

Grâce aux appels à `printf`, en utilisant l'entrée `%p-%p-%p-%p-%p-%p-%p-%p-%p-%p` nous savons que :

- l'index **n°5** contient la valeur de `stack_var`;
- l'index **n°6** contient son adresse, à savoir `stack_addr`.

Ce qui nous intéresse n'est pas tant la modification `stack_var`mais plutôt l'affichage de sa valeur depuis la chaîne de format **après** sa modification :

```
# En utilisant un parametre positionnel
$ ./exe

stack_var (avant) : 0xdeadbeef

stack_addr : 0xfff803b4
aaaaaa %6$n [%5$p]
aaaaaa  [0xdeadbeef]

stack_var (apres) : 0x7
```

`stack_var`a bien été modifiée. Néanmoins, lorsque l'on affiche sa valeur depuis la chaîne de format avec `%5$p`, c'est toujours `0xdeadbeef`qui est affiché alors la valeur venait juste d'être modifiée par `%6$n`. 

> C'est parce que la pile **a été copiée** j'imagine ?
{: .prompt-info }

C'est ça ! Voici, en revanche, ce qui se passe **sans utiliser** de paramètre positionnel (pour modifier la valeur):

```
# Sans utiliser de parametre positionnel
./exe

stack_var (avant) : 0xdeadbeef

stack_addr : 0xff9011d4
%p-%p-%p-%p-%p-%n-[%5$p]
0x100-0xf654a5c0-0x649b41c8-0x6-0xdeadbeef--[0x2b]

stack_var (apres) : 0x2b
```

Cette fois-ci, en utilisant `%5$p`pour afficher le contenu de `stack_var`, c'est bien la valeur modifiée qui est affichée ! Tout simplement parce que **l'on n'a pas utilisé de paramètre positionnel** jusque-là. Ainsi, la pile n'a pas encore été copiée. Elle ne sera copiée qu'au moment de traiter `%5$p`car un paramètre positionnel y est utilisé.

Dans le premier exemple, la pile a été copiée au moment de traiter `%6$n`, la valeur de `stack_var`était, à ce stade, **toujours égale** à `0xdeadbeef`. Tandis que dans le dernier exemple, lors de la copie de la pile, la valeur de `stack_var`avait **déjà été modifiée** précédemment sans avoir besoin d'utiliser de paramètre positionnel.

Bref, tout ça pour dire que dès que la `libc` **tombe sur un paramètre positionnel** dans la chaîne de format, elle **copie aussitôt le contenu de la pile**.

C'est une information importante car vous risquez de vous arracher les cheveux dans les cas où vous devez **modifier une valeur** sur la pile puis **la réutiliser plus tard** dans la même chaîne de format.

![](/assets/images/introduction_au_pwn/meme_fmt.png)