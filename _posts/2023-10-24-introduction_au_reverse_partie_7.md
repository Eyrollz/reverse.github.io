---
title: Partie 7 - Analyse statique  d'un mini-programme - la pile (3/5)
date: 2023-10-24 10:00:00
categories: [Reverse, Introduction au reverse]
tags: [x86, reverse, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# Analyse statique  d'un mini-programme  : la pile (3/5)

> On va garder IDA encore ouvert très longtemps sans rien faire ?
{: .prompt-info }

Allez, encore un peu de théorie nécessaire avant de revenir au *reverse* de notre programme. En effet, si on ne comprend pas le fonctionnement de la pile, on ne pourra jamais comprendre :

- comment les **variables locales** sont utilisées
- comment les **arguments** sont transmis et utilisés
- comment une fonction **retourne**
- etc.

Contrairement au tas, la pile (ou pile d'exécution ou *stack* 🇬🇧) **porte bien son nom** car elle utilise effectivement la structure de donnée qu'est [la pile](https://fr.wikipedia.org/wiki/Pile_(informatique)). C'est-à-dire qu'il s'agit d'une zone mémoire de type **LIFO** (Last In First Out) ou **Dernier Arrivé Premier Servi**.

## Empiler et dépiler

Je vous propose d'utiliser plusieurs exemples afin de comprendre son fonctionnement.

> Par souci de clarté, nous nous limiterons à une analyse de la version **32 bits** de pile étant donné que le fonctionnement en 64 bits est exactement le même.
> 
> La seule différence entre la pile en 32 bits et 64 bits est **la taille maximum** de chaque élément qu'elle peut stocker (respectivement 32 et 64).
{: .prompt-tip }

Prenons une pile pouvant contenir jusqu'à 6 éléments. Si vous vous souvenez, la convention fait que les adresses basses sont situées en haut alors que les adresses hautes en bas.

![](/assets/images/introduction_au_reverse/monde-envers.gif)

Imaginons que la pile contienne **un seul élément** pour l'instant, nous avons donc ceci en mémoire :

![](/assets/images/introduction_au_reverse/pile_1_bis.png)

Supposons que l'élément non vide provienne d'une fonction A mais que nous sommes désormais dans le code d'une fonction B. Alors `esp` et `ebp` sont confondus et pointent vers le haut de la pile.

> Très souvent, pour ne pas dire tout le temps, lors de l'entrée dans une nouvelle fonction la pile a cette allure (après exécution du **prologue**), c'est-à-dire que `esp` et `ebp` pointent vers le haut de la pile.
> 
> C'est en partie à cela que sert le **prologue** d'une fonction : avoir un nouvel état "*clean*" de pile.
{: .prompt-tip }

> Le haut de la pile n'est pas `0x70000100` car le haut de la pile est la dernière valeur ajoutée sur la pile.
{: .prompt-warning }

Ajoutons quelques éléments à notre pile ! Par exemple :

1. l'entier `0xdeadbeef`
2. l'entier nul `0x00000000`
3. le caractère `A`

Voyons tout d'abord l'état de la pile après avoir ajouté `0xdeadbeef` :

![](/assets/images/introduction_au_reverse/pile_2_bis.png)

Désormais, le haut de la pile est l'adresse qui pointe vers `0xdeadbeef` et qui est donc `0x70000110`, c'est pourquoi `esp` pointe vers cette adresse.

Pour rappel :
- `esp` pointe vers le **haut de la pile**
- `ebp` pointe vers la **base de la pile**

> Ce n'est pas à nous de mettre à jour à chaque fois `esp` pour qu'il pointe vers le haut de la pile. Cela est en effet réalisé automatiquement lorsque l'on ajoute (empile) une valeur sur la pile.
{: .prompt-tip }

Maintenant, ajoutons nos deux autres éléments : `0x00000000` puis `A`. L'état de la pile est alors le suivant :

![](/assets/images/introduction_au_reverse/pile_3_bis.png)

Pour l'instant, c'est logique, tout va bien. Désormais je souhaite récupérer la valeur `0x00000000` de la pile. Le soucis est qu'en raison de la structure de données qu'est la pile, nous ne pouvons pas accéder directement à n'importe quelle valeur. En effet, seules deux opérations sont possibles :

- **Empiler** : ajouter un élément en haut de la pile. Cette opération est réalisée avec l'instruction assembleur `push ELT` où `ELT` est l'élément mis en tête de la *stack*, exemple : `push 0xdeadbeef`. `ELT` peut être soit une valeur concrète comme `0xdeadbeef` soit un registre comme `rax` auquel cas c'est la **valeur contenue** dans le registre qui est insérée en haut de la pile.
- **Dépiler** : retirer un élément du haut de la pile. Cette opération est réalisée avec l'instruction assembleur `pop DEST` où `DEST` est la destination où sera stocké l'élément retiré. `DEST` est toujours un **registre**.

Ainsi, pour accéder à `0x00000000`, il va falloir **dépiler une première fois** pour récupérer `A` (nous ne sommes pas obligés d'en faire quelque chose) puis **dépiler une deuxième fois** pour avoir accès à la valeur qui nous intéresse.

Si je souhaite stocker `0x00000000` dans `edi`, par exemple, je peux faire :

```nasm
pop edi ; edi = 0x41 (encodage ASCII de 'A')
pop edi ; edi = 0x00000000
```

La pile aura ensuite l'allure suivante : 

![](/assets/images/introduction_au_reverse/pile_4_bis.png)

## La stack frame

A présent que nous avons les idées plus claire sur la pile (*stack*), intéressons-nous à une manière d'utiliser la *stack* afin de bien gérer les appels de fonction, les variables locales et les arguments : la *stack frame* (ou cadre de pile 😴).

L'idée globale est que chaque fonction puisse pouvoir **gérer** de **manière autonome** :

- ses **variables locales**
- l'accès aux **arguments**

Prenons un exemple concret avec le code suivant qui calcul le [discriminant](https://fr.wikipedia.org/wiki/Discriminant) d'un polynôme du second degré :

```cpp
#include "stdio.h"  
  
int discriminant(int a, int b, int c)  
{  
	 int result = b*b - (4*a*c);  
	 return result;  
}  
  
int main()  
{  
	// Le polynôme : x² + 10x + 3  
	int a = 1;  
	int b = 10;  
	int c = 3;  
	
	int result = discriminant(a,b,c);  
	
	printf("Le discriminant de mon polynôme est %d\n",result);  

}
```

Supposons que l'état de la pile avant l'appel à la fonction `discriminant(a,b,c)` soit dans un état quelconque :

![](/assets/images/introduction_au_reverse/pile_5_bis.png)

La question que l'on peut se poser est : comment appeler la fonction `discriminant` en faisant en sorte qu'elle ait sa propre *stack frame* sans empiéter sur celle de la fonction `main` ? La réponse à cette question est exactement ce que vont faire **l'appel à la fonction** ainsi que son **prologue**.

### 📣 L'appel de fonction

Je vous propose de décortiquer la manière dont **l'appel à la fonction** `discriminant` est effectué en x86 :

1. **Ajout des arguments** : tout d'abord, il va bien falloir que d'une façon ou d'une autre, la fonction `discrimiant` puisse avoir accès aux trois arguments.
2. **Ajout de l'adresse de retour** : une fois que la fonction `discriminant` sera exécutée, il faut qu'elle puisse retourner à l'instruction qui est située immédiatement après son appel dans la fonction `main`
3. **Création de la *stack frame*** de `discriminant` : la fonction `discriminant` a besoin d'un minimum d'espace pour stocker son unique variable locale.

Ajout des arguments :

![](/assets/images/introduction_au_reverse/pile_6_bis.png)

> Comme la pile est une structure de données de type "Dernier Arrivé Premier Servi", le dernier argument `3` est empilé en premier. Puis le deuxième argument `10` est empilé. Enfin, le premier argument `1` est empilé en dernier.
{: .prompt-tip }

Ajout de la valeur de retour :

![](/assets/images/introduction_au_reverse/pile_7_bis_.png)

> Il ne faut pas confondre **adresse de retour** et **valeur de retour** qui sont deux choses totalement différentes.
> 
> La **valeur de retour** est le résultat retourné par une fonction, par exemple `-1` dans  `return -1;`. La valeur de retour est toujours retourné via `eax` (et ses dérivées) sauf exception.
> 
> L'**adresse de retour** est l'adresse de l'instruction, dans la fonction appelante, que le processeur va exécuter une fois que la fonction appelée est terminée.
{: .prompt-warning }

Ok super ! Nous sommes dorénavant prêts pour rentrer dans le code de la fonction `discriminant`. Tout d'abord, comme vous pouvez le constater, `esp` et `ebp` pointent vers les adresses de début et de fin de la *stack frame* de `main`. Il ne faudrait donc pas qu'en créant notre nouvelle *stack frame* perdre ces informations. Nous allons donc les stocker sur la pile.

> En fait nous n'avons besoin que de stocker `ebp` car, lorsque l'on quittera la fonction `discriminant`, `esp` retombera naturellement sur la valeur qu'il avait avant d'entrer dans la fonction.
{: .prompt-tip }

### Le prologue

Vous vous souvenez du prologue ? C'étaient les instructions :

```nasm
push ebp
mov ebp, esp
sub esp, 0x10
```

Après avoir sauvegardé `ebp` avec `push ebp`, la pile est dans cet état :

![](/assets/images/introduction_au_reverse/pile_8_bis.png)

Ensuite, le processeur va créer une nouvelle *stack frame* en initialisant `ebp` à la même valeur que `esp` via `mov ebp, esp`. 

Cette instruction déplace (copie) le contenu de `esp` dans `ebp`, la pile devient alors de la sorte :

![](/assets/images/introduction_au_reverse/pile_9_bis.png)

Bon, pour l'instant c'est pas fameux, on ne voit pas la *stack frame* de la fonction `discriminant` par ce qu'elle est  ... tout simplement vide ! Or nous avons besoin d'un peu d'espace pour les variables locales, en l’occurrence ici LA variable locale `resultat`.

Dans le prologue, c'est l'instruction `sub esp, 0x10` qui se charge de réserver un tel espace pour les variables locales en soustrayant `esp` de l'espace désiré. Ici cela revient à faire `esp = esp - 0x10`.

> Pour rappel, comme les **adresses basses sont en haut** et inversement, pour **augmenter** la taille de la pile on **soustrait** à `esp`
> 
> Tandis que lorsque l'on souhaite **réduire** la taille de la pile, on **ajoute** à `esp`.
{: .prompt-tip }

Enfin, la *stack frame* de `discriminant` est la suivante :

![](/assets/images/introduction_au_reverse/pile_10_bis.png)

> On aurait pu, sur le schéma, inclure `Adresse de retour` dans la *stack frame* de `discriminant`. Le choix de ne pas l'inclure permet de garder en tête que la *stack frame* courante est tout l'espace compris entre les valeurs pointées par `esp` (qui en délimite le haut) et `esp` (qui en délimite la base)
{: .prompt-tip }

> J'ai pas très bien compris pourquoi on étend la pile de 16 (`0x10`) octets alors que l'on a qu'une seule variable locale `int result` qui est de 4 octets ?
> C'est pas très écolo tout ça !
{: .prompt-info }

Excellente question et qui a dû en perturber plus d'un (et j'en fais partie 😅) ! En fait c'est une **question d'alignement**.

Le processeur aime bien que `esp` soit aligné sur 8 bits, c'est-à-dire qu'il ait la forme suivante : `0xXXXXXXX0`. Autrement dit, que `esp` soit un multiple de 16. C'est pourquoi que l'on ait **4, 8 ou 12 octets** de variables locales, le processeur réservera **16 octets**.

> Dans la même optique d'aligner `esp`, vous verrez peut-être dans le prologue de certaines fonctions une instruction `and esp, 0xfffffff0` qui réalise un **ET logique** de telle sorte à ce que `esp` soit aligné sur 16 octets.
{: .prompt-tip }

A partir de maintenant, le prologue est terminé et il est possible de récupérer les arguments, stocker les variables locales, faire des calculs etc.

Ainsi tout **l'espace mémoire** entre `ebp` et `esp` peut être utilisé pour **stocker des variables locales**.

### L'épilogue

Pour rappel, une fonction est constituée de 3 parties :

1. Le **prologue**
2. Faire des **trucs** (calculs, stockage ...)
3. L'**épilogue**

En découpant la fonction `main` de notre premier programme (celui qui fait une addition et retourne la somme) ouvert dans IDA, nous identifions bien ces **3 étapes distinctes** :

![](/assets/images/introduction_au_reverse/etapes_fonction.png)

Intéressons nous à l'épilogue qui est :

```nasm
leave
ret
```

Il faut savoir que `leave` n'est pas une **instruction atomique**. Cela signifie que lorsque le processeur exécute cette instruction, il exécutera en réalité plusieurs instructions.

En l'occurrence l'instruction `leave` est totalement équivalente (en 32 bits) à :

```nasm
mov esp, ebp
pop ebp
```

> Ah mais c'est exactement l'inverse de ce qu'a fait le prologue ?
{: .prompt-info }

C'est ça !

Pour rappel le prologue est (en partie) :

```nasm
push ebp
mov ebp, esp
```

L'instruction `mov esp, ebp` permet de **mettre fin** à la *stack frame* courante en mettant `esp` à la base de celle-ci. Tandis que l'instruction `pop ebp` permet de **restaurer l'ancienne** valeur de `ebp` : celle de la *stack frame* de la fonction `main`.

> Il n'y a pas besoin "d'inverser" l'instruction `sub esp, 0x10` car le fait de faire `mov esp, ebp` implique que `esp` pointe désormais vers le bas de la *stack frame*, indépendamment de la valeur qu'il avait auparavant.
{: .prompt-tip }

L'instruction `leave` permet ainsi de "sortir", comme son nom l'indique, de la `stack frame` de la fonction appelée. Si on reprend notre exemple avec la fonction `main` et `discriminant`, après l'instruction `leave` la pile d'exécution a cette tête :

![](/assets/images/introduction_au_reverse/pile_11_bis_.png)

Il ne nous reste plus qu'à exécuter l'instruction `ret`. En fait, pour aller droit au but, l'instruction `ret` est exactement équivalente à faire `pop eip`.

Or vous vous souvenez, `eip` pointe vers l'instruction qui va être prochainement exécutée. Ainsi, après l'exécution de `ret`, `eip` sera égal à l'**adresse de retour** qui est, pour rappel, l'adresse dans le `main` après l'appel de fonction.

Vu que `ret` dépile l'adresse de retour, la *stack frame* de la fonction `main` est restée intacte du début à la fin de l'appel de la fonction `discriminant`.

> Comme c'est la fonction `main` qui s'est chargée de mettre les arguments sur la pile, c'est à elle de s'en débarrasser 😏 !
> 
> Même si, en réalité, ce n'est pas toujours le cas, en effet, dans certaines situations, c'est à la fonction appelée de s'en charger. Nous verrons cela un peu plus tard.
{: .prompt-tip }

## 📋 Synthèse

Nous venons de voir le fonctionnement de la pile dans le contexte de l’exécution d'un programme. Plusieurs points ont été vus :

- La pile d'exécution est une structure du type **LIFO** : Dernier Arrivé Premier Servi
- Seules **deux opérations** sont possibles : **empiler** (avec `push`) et **dépiler** avec `pop`
- Chaque fonction a sa **propre zone mémoire** dédiée dans la pile nommée ***stack frame***
- L'exécution d'une fonction est réalisé en **3 étapes** :
	- **Prologue**
	- Autres **opérations** quelconques
	- **Épilogue**
- Les registres `esp` et `ebp` permettent, entre autres, de **délimiter** respectivement le **haut** et la **base** d'une *stack frame*

## ➕ Bonus

On vient de voir qu'une *stack frame* est créée à chaque appel d'une fonction. Ainsi, si une fonction récursive (qui s'appelle elle-même) est appelée sans fin, cela va consommer de la mémoire pour chaque *stack frame* : c'est tout simplement ce que l'on appelle un ***stack overflow*** ! 

Voilà, vous savez désormais ce que signifie et d'où provient le nom du site éponyme😎.
