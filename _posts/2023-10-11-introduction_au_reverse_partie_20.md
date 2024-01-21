---
title: Partie 20 - L'analyse dynamique - débogage d'un programme (2/4)
date: 2023-10-11 10:00:00
categories: [Reverse, Introduction au reverse]
tags: [x86, reverse, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# L'analyse dynamique : débogage d'un programme (2/4)

Et si on laissait la théorie de côté un instant et que l'on mettait la main à la pâte, ça vous dit ?

> Dans ce chapitre nous allons découvrir de nombreuses **commandes** propres à gdb, je vous propose de les noter dans un coin (feuille de brouillon, notes ...), cela vous sera très utile quand vous déboguerez un programme de votre côté.
> 
> Dans tous les cas, elles sont présentes dans les annexes de ce cours.
{: .prompt-tip }

Tout d'abord, si ce n'est pas déjà le cas, installez **gdb**. Pour les distros debian like : `sudo apt install gdb`. Je vous propose également d'installer l'extension [pwndbg](https://github.com/pwndbg/pwndbg).

En effet, la version **gdb de base**, bien que fonctionnelle, n'est **pas du tout ergonomique** :

- il faut toujours afficher les registres **soit même**
- les instructions autour de l'instruction en cours d'exécution ne sont **pas affichées**
- et puis, ça manque de **couleurs** de tout ça !

Ainsi, **pwndbg** va nous faciliter la vie et nous permettre d'aller plus vite. Pour installer **pwndbg** il suffit de suivre les instructions d'installation sur leur dépôt GitHub.

> Il ne faut pas confondre **pwndbg** et **pwngdb** qui sont deux extensions différentes de gdb.
> 
> Il est possible d'utiliser les deux en même temps afin d'avoir plus de fonctionnalités mais il semblerait que `pwngdb` ne soit pas assez à jour pour être utilisé avec **pwndbg** actuellement.
> 
> Si vous trouver une manière d'installer les deux dans leur version récente, je suis preneur 😅 !
{: .prompt-warning }

Une fois l'installation terminée, nous pouvons faire joujou avec notre nouveau jouet.

Je vous propose de tester gdb avec le programme suivant :

```cpp
#include "stdio.h"
int calcul(int a, int b, int c)  
{  
 return a + b*c;  
}  

int main()  
{  
  
 int a = 1;  
 int b = 2;  
 int c = 3;  
  
 calcul(a,b,c);  
    
 a = 4;  
 b = 5;  
 c = 6;  
    
 calcul(a,b,c);  
  
 a = 7;  
 b = 8;  
 c = 9;  
    
 calcul(a,b,c);  
  
 puts("Travail terminééééé !");  
  
 return 0;  
}
```

Compilons-le avec `gcc main.c -o exe`.

## Démarrage du débogage

Pour commencer à déboguer notre programme fraîchement compilé, il suffit de lancer `gdb ./exe`. Vous devriez avoir quelque chose qui ressemble à ceci :

![](/assets/images/introduction_au_reverse/gdb_init.png)

> Ok mais où est notre programme débogué ? Je le vois nulle part ! 😴
{: .prompt-info }

C'est normal ! A ce stade, **gdb** est à peine lancé et a lu les différents symboles (noms de fonctions, variables globales ...) présents dans le programme. 

Nous pouvons lancer l'exécution du programme débogué avec la commande `run`.

> Si un programme accepte des arguments via `argv`, il est possible de les spécifier lors de la commande `run`.
> 
> Exemple : `run arg1 arg2`
{: .prompt-tip }

On obtient ceci :

![](/assets/images/introduction_au_reverse/run_gdb.png)

Notre programme s'est bien exécuté !

> C'est un blague ! Tu nous as dit qu'on allait pouvoir lire la valeur des registres, inspecter la mémoire etc. mais on a eu rien de tout ça ! On aurait eu exactement le même résultat en l'exécutant normalement 😠 !
{: .prompt-info }

Alors effectivement exécuter un programme d'une traite dans gdb n'est pas ce qu'il y a de plus intéressant. Commençons donc à voir ce qu'il propose afin de comprendre en quoi l'analyse dynamique est très utile.

## 🔴 Les points d'arrêt

Les points d'arrêt (ou *breakpoints* 🇬🇧) sont des marqueurs placés sur certaines instructions (plus précisément sur l'adresse de l'instruction). Lorsque le processus atteindra l'instruction sur laquelle il y a un point d'arrêt (`rip == addr_marquée `), gdb va suspendre l'exécution du programme. Cela nous permet ensuite de pouvoir analyser pas mal de choses.

Il existe principalement deux types de *breakpoints* :

- Les **hardware breakpoints** (points d'arrêts matériels)
- Les **software breakpoints** (points d'arrêts logiciels)

Le point commun entre les deux est que lorsque le processus arrivera à un point d'arrêt, matériel ou non, l'exécution sera stoppée. La différence entre les deux est la manière dont ils sont implémentés.

Pour faire simple :

- Les points **d'arrêt logiciels** sont implémentés via l'insertion artificielle d'une instruction permettant stopper l'exécution du programme. En x86, cette instruction est l'interruption `int 3` dont l'opcode est `0xcc`.
- Les points **d'arrêt matériels** sont implémentés via des [registres du processeur dédiés](https://en.wikipedia.org/wiki/X86_debug_register) à cet effet : `DR0`, `DR1`, `DR2` ... Ainsi, nul besoin d'insérer une instruction dans le code.

Dans le cas d'un programme protégé (*crackme*, *malware*, programme propriétaire, jeu vidéo ...), il est plus facile de détecter les points d'arrêt logiciels (en raison de l'insertion de `int 3`) que les matériels (mais pas impossible !). Ainsi, si vous pensez que le programme que vous analysez est protégé, il vaut mieux commencer par utiliser des **points d'arrêt matériels** avant d'utiliser les points d'arrêt logiciels.

> **Astuce gdb** : La commande `hb *0xaddr` (*hardware breakpoint*) permet d'insérer un point d'arrêt matériel à l'adresse `0xaddr` .
{: .prompt-tip }

Le souci des *hardware breakpoints* est qu'il y en a un nombre limité (car il y a un nombre limité de registres de débogage) et que tous les processeurs ne supportent pas cette fonctionnalité. En revanche, les *softwares breakpoints*, en veux-tu en voilà !

> Dans la suite de cours, par souci de concision, le terme point d'arrêt (*breakpoint*) désignera un point d'arrêt logiciel.
{: .prompt-tip }

### L'insertion de points d'arrêts

Nous pouvons utiliser le raccourcis `b nom_de_fonction` de gdb afin d'insérer un point d'arrêt au niveau de la **première instruction** de la fonction ci celle-ci dispose d'un symbole.

> **Astuce gdb** : Pour les fonctions dont le symbole n'est pas disponible (ex: programme *strippé*), il est possible d'utiliser l'adresse de la fonction : `b *0x401020`.
> 
> Notez bien l'astérisque avant l'adresse. Elle est indispensable lorsque l'on utilise des adresses sinon gdb ne va pas aimer du tout.
> 
> En temps normal, si un programme est **PIE**, l'adresse du `main` changera à chaque exécution à cause de l'**ASLR**. Heureusement **pwndbg** désactive automatiquement l'ASLR à chaque fois que l'on ouvre **gdb**. Vous pouvez **activer l'ALSR** avec la commande : `set disable-randomization off`.
{: .prompt-tip }

Cette fois-ci, avant de lancer l'exécution, mettons un point d'arrêt sur la fonction `main` afin de stopper l'exécution une fois arrivés à sa première instruction :

![](/assets/images/introduction_au_reverse/b_main.png)

> **Astuce gdb** : Vous pouvez utiliser `i b` (pour `info breakpoints`) afin de lister les points d'arrêts du programme.
> 
> Cela est très utile pour s'y retrouver. Chaque point d'arrêt ayant un numéro unique, il sera affiché dans cette commande.
{: .prompt-tip }

> **Astuce gdb** : Pour supprimer un point d'arrêt vous pouvez utiliser  `d N` (pour `delete N`) afin de supprimer le *breakpoint* numéro `N`.
{: .prompt-tip }

Le point d'arrêt est en place, lançons le programme avec `run` et là ...

![](/assets/images/introduction_au_reverse/pikachu.png)

## Comprendre l'interface de gdb (pwndbg)

Alors oui, de prime abord cela peut paraître surprenant mais vous verrez que ce sont des informations **très utiles** ! Essayons de les décortiquer ensemble.

![](/assets/images/introduction_au_reverse/pwndbg.png)

- **Point d'arrêt déclenché** : le numéro du point d'arrêt **atteint** et l'adresse à laquelle l'exécution du processus a été arrêtée.
- **Registres** : la liste des principaux registres. Quand le registre contient une adresse (pointeur) valide, gdb la déréférence et ainsi de suite. Par exemple, ici, `rsi` contient `char **argv`, c'est pourquoi on a `rsi = argv -> &argv[0] -> chemin_du_programme`.
- **Prochaine instruction exécutée** : le nom est explicite. Nous verrons plus tard comment exécuter des instructions pas à pas.  
- **Instructions suivantes désassemblées** : il s'agit des instructions suivantes qui peuvent être exécutée. C'est plutôt sympa qu'elles soient désassemblées et affichées directement, cela nous permet de nous situer plus facilement dans le code.
- **Premières valeurs de la pile** : ça peut être pratique d'avoir les premières valeurs sous le nez, notamment pour y lire les arguments lorsqu'ils sont transmis de cette manière (ex : x86).
- **Trace d'appels** : si vous vous rappelez du chapitre sur la pile, vous devriez vous souvenir que lors de l'appel d'une fonction, une *stack frame* est mise en place afin de gérer les variables locales de la fonction appelée ainsi que le retour de fonction vers la fonction appelante. En l'occurrence, dans cet endroit vous avez les différents appels de fonctions qui ont précédés l'appel à `main`. 

Vous remarquerez, si vous jetez un œil à la deuxième ligne, que **pwndbg** utilise un **code couleur** ma foi très utile pour savoir où se situe et ce que contient une adresse ou zone mémoire.

> **Astuce gdb** : Vous pouvez lister les zones mémoire mappées avec la commande `libs`.
{: .prompt-tip }

## Avancer dans un processus dans gdb

Parfois, l'utilisation des *breakpoints* ne suffit pas à analyser correctement le comportement d'un programme. Il faut alors une granularité d'exécution encore **plus fine**. Ça tombe bien, gdb nous permet d'exécuter **pas à pas** un programme, c'est-à-dire **instruction par instruction**.

Cela est très utile pour diverses raisons :

- Comprendre **ce que fait une instruction**
- Voir les **registres modifiés** par une instruction
- Dans le cas de **sauts dynamiques** (ex : `call rax`), voir où l'on risque de sauter après l'exécution de l’instruction
- Voir laquelle des **deux branches** va être prise lors d'un saut (ex : `jz 0x405030`)

Tout d'abord, il y a une instruction très utile lorsque l'on souhaite charger en mémoire un programme dans gdb sans commencer à l'exécuter.

> **Astuce gdb** : L'instruction `starti` permet de charger le programme en mémoire et de **s'arrêter à la première instruction** de ce dernier, **sans l'exécuter**.
{: .prompt-tip }

Cette commande est très utile pour charger le programme et voir où est chargé le programme (et donc l'adresse du `main`) via la commande `libs`.

> Si vous n'arrivez pas à comprendre ce que représentent les premières lignes de ce qu'affiche `libs`, je vous invite à jeter un œil au chapitre `Les segments et sections` que l'on a vu à la page 3 (ou autour) pour vous rafraîchir la mémoire 😊. 
{: .prompt-tip }

Je vous propose de quitter gdb puis rouvrir `exe` dans gdb et lancer `starti`.

> **Astuce gdb** : Vous pouvez quitter gdb avec les commandes `quit` ou `exit`. De manière plus rapide, vous pouvez utiliser `Ctrl+D`.
{: .prompt-tip }

Normalement vous devriez avoir plus ou moins ceci avec la commande `libs` (tronqué):

![](/assets/images/introduction_au_reverse/libs_out.png)

### 🔄 Synchroniser gdb et IDA

J'en profite un instant pour vous partager une astuce pour ne pas avoir de soucis de "désynchronisation" entre les adresses utilisées par IDA et celle dans gdb.

En ouvrant le programme `exe` dans IDA on voit que la fonction `main` est à l'adresse `0x116A` (peut différer chez vous) alors que dans gdb elle est à l'adresse `0x55555555516a` : 

![](/assets/images/introduction_au_reverse/p_main.png)

> Nous verrons un peu plus tard en détails comment **afficher** des valeurs, pointeurs, registres dans gdb. 
{: .prompt-tip }

> Comment faire alors pour les adresses affichées dans gdb et IDA concordent ?
{: .prompt-info }

Une solution est la suivante : rebaser notre programme dans IDA en utilisant la base de gdb. Ce que l'on entend par **base** est **l'adresse de base** (merci Sherlock 🕵️‍♂️) à laquelle est chargé le programme. Il s'agit de la première adresse affichée par `libs`, dans mon cas c'est `0x555555554000`.

En effet, comme le programme est PIE, l'adresse de chaque instruction n'est en fait qu'un offset par rapport à l'adresse de base du programme (plus précisément du segment de code).

> **Astuce IDA** : Une fois que vous avez trouvé l'adresse de base de votre programme, il suffit, dans IDA, d'aller dans `Edit` ➡️ `Segments` ➡️ `Rebase program` puis saisir l'adresse de base trouvée dans gdb avec `libs` et cliquer sur `Ok`.
> 
> Tadaaa ! Les adresses des instructions, fonctions etc. sont désormais les mêmes !
{: .prompt-tip }

Cette astuce vous sera très utile lorsque vous manipulerez des programme PIE *strippés* et que vous ne pourrez plus vous contenter d'un simple `b main` pour mettre un point d’arrêt sur le `main` 😎.

### 👣 Avancer pas à pas dans un processus

Il existe **différentes** manière d'**avancer** dans l'exécution d'un programme dans gdb, parmi celles-ci il y a :

- avancer **d'une instruction**
- avancer jusqu'à **rencontrer un point d'arrêt**
- avancer jusqu'à **sortir de la fonction** courante

#### ⏯️ Avancer d'une instruction

> **Astuce gdb** : Pour exécuter l'instruction courante et s'arrêter à la prochaine, il est possible d'utiliser `si` ou `ni` (pour `step instruction` et `next isntruction`).
> 
> La différence entre les deux est que lors de l'appel d'une fonction, `ni` exécute la fonction jusqu'au retour alors que `si` entre dans la fonction et s'arrête à la première instruction.
{: .prompt-tip }

En utilisant `si`, il est possible d'exécuter pas à pas le programme et voir les registres modifiés qui sont alors affichés en rouge 🔴 alors que ceux qui n'ont pas été modifiés depuis sont affichés en blanc ⚪. 

> **Astuce gdb** : Le fait de saisir à chaque fois `si` pour avancer d'une instruction peut être fastidieux 😤. Vous pouvez ~~spammer~~ utiliser la touche `Entrée` dans le terminal gdb afin de ré-exécuter la dernière commande que vous avez lancée précédemment.
{: .prompt-tip }

#### ⏭️ Avancer jusqu'au prochain point d'arrêt 

Quand un programme est **volumineux** ou que certaines boucles ou fonctions sont **longues**, avancer instruction par instruction se révèle beaucoup **trop long**. Il est alors possible de mettre un point d'arrêt vers l'adresse que l'on souhaite atteindre et poursuivre l'exécution jusqu'à celle-ci.

> **Astuce gdb** : Vous pouvez utiliser la commande `c` (ou `continue`) pour poursuivre l'exécution du processus jusqu'à arriver à un point d'arrêt.
{: .prompt-tip }

> Lorsque vous mettez un point d'arrêt sur une adresse en vue de vous y arrêter en lançant `c`, il se peut que le point d'arrêt ne soit pas atteint auquel cas le programme termine (ou fasse autre chose).
> 
> Imaginez que vous souhaitiez vous arrêter à la fonction de chiffrement d'un rançongiciel en y mettant un point d'arrêt mais que vous vous êtes trompés de fonction ou que plusieurs fonctions de chiffrement sont disponibles. Le fait de poursuivre avec `c` va continuer l'exécution sans s'arrêter et là, bonjour les dégâts  ☢️☣️💣 !
> 
> Pour prévenir ce genre de scénarios, quand vous analysez du code dangereux, assurez-vous de mettre des garde-fous pour ne pas exécuter le reste du programme. 
{: .prompt-danger }

Nous avions vu la commande `run` pour lancer un programme. Si des points d'arrêt sont déjà présents dans le programme et qu'ils sont atteints, alors `run` s'y arrêtera.

#### ⤴️Avancer jusqu'au sortir de la fonction courante

Quand on fait du *reverse* en analyse dynamique, on veut souvent aller vite et ne pas perdre de temps à analyser du code qui n'est pas intéressant. Ainsi, si on se retrouve dans une fonction que l'on a déjà analysée ou dans une fonction de la libc, par exemple, il n'y a pas tellement **d'intérêt** à exécuter toute la fonction instruction par instruction.

Une méthode fastidieuse serait de mettre un point d'arrêt à l'adresse où retourne la fonction une fois qu'elle a fini son exécution mais cela implique de trouver l'adresse en question.

Une méthode plus simple est d'utiliser la commande `finish`.

> **Astuce gdb** : Vous pouvez utiliser le raccourcis `fin` (ou `finish`) pour finir l'exécution d'une fonction jusqu'à atteindre l'adresse de retour et s'y arrêter.
{: .prompt-tip }

## 📝 Exercice 

Je vous propose de réaliser  un petit exercice pour vous familiariser un peu avec gdb et les commandes de déplacement.

🎯 **L'objectif** :  retrouver les arguments de chaque appel à la fonction `calcul` en **analyse dynamique** seulement.

Comme ça c'est facile, on a le **code source** sous les yeux et le cas échéant on pourrait décompiler le programme pour savoir la réponse. Mais le but est de faire l'exercice en s'aidant **seulement de gdb**.

💪 Si vous souhaitez vous **entraîner davantage**, vous pouvez *stripper* le programme afin de retirer les symboles et apprendre à mettre des points d'arrêt en utilisant les adresses. 

💡 **Astuce n°1**  

`UXVlbGxlIGVzdCBsYSBjb252ZW50aW9uIGQnYXBwZWwgdXRpbGlzw6llID8gT8O5IGRldnJhaWVudCBkb25jIMOqdHJlIHN0b2Nrw6lzIGxlcyBhcmd1bWVudHMgPw==`

💡 **Astuce n°2**

`QXZvbnMtbm91cyByw6llbGxlbWVudCBiZXNvaW4gZCdleMOpY3V0ZXIgbGEgZm9uY3Rpb24gImNhbGN1bCIgcGFzIMOgIHBhcyA/`

