---
title: Partie 4 - Exploiter un BO - pile exécutable – principes fondamentaux (1/4)
date: 2026-05-05 10:00:00
categories: [Pwn, Introduction au pwn]
tags: [x86, pwn, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# Exploiter un *stack buffer overflow* : pile exécutable – principes fondamentaux (1/4)

![](/assets/images/introduction_au_pwn/pwn_t_2.png)

> Tu nous as promis d'apprendre à exploiter des vulnérabilités pour ouvrir un *shell* et devenir *root*, pas pour juste afficher un simple message ... 
{: .prompt-info }

On y vient ! On a vu précédemment le principe du **dépassement de mémoire tampon sur la pile** et la manière dont on pouvait exploiter ça. Cela ne devrait donc pas totalement vous dépayser **d’exploiter ce type de vulnérabilité avec une nouvelle méthode**. C'est une méthode qui, telle quelle, n'est plus d'actualité car de nos jours **la pile n'est généralement plus exécutable**. Cependant, dans les cas où il est possible d’allouer de la mémoire exécutable (avec `mmap` ou `mprotect` par exemple), nous pourrons toujours **réutiliser cette méthode**.

> Dans le cadre de l'exploitation des différentes vulnérabilités que nous allons rencontrer, nous **désactiverons certaines protections** afin de faciliter l'exploitation. De ce fait, cela va **réduire la sécurité** de votre machine.
> 
> Encore une fois, nous vous **conseillons vivement** de mettre en place une **machine virtuelle** qui vous servira de labo de test. Pour ce qui est de l'OS à choisir, vous pouvez opter pour une distribution **Ubuntu 24.04 x86_64** afin de maximiser la compatibilité des programmes que nous exploitons.
> 
> De manière générale, n'importe quelle distribution "**Debian like**" récente devrait fonctionner. Le cas échéant, en utilisant les conteneurs Docker proposés, vous ne devriez avoir aucun souci de compatibilité.
{: .prompt-tip }

Le programme que nous allons utiliser est le suivant :

```cpp
#include "stdio.h"  

int main()  
{  
 char prenom[256] = {0};  // /!\ augmentation de la taille
 gets(&prenom);  
 printf("Bonjour %s !\n",prenom);  
 return 0;  
}
```

On le compile avec : `gcc -m32 -no-pie -fno-stack-protector -z execstack main.c -o vuln_no_nx`.

> Si vous n'arrivez pas à compiler en 32 bits, il est possible que vous deviez installer le paquet `gcc-multilib` (pour les distributions de type Debian).
{: .prompt-tip }

Pour télécharger l'archive du conteneur Docker, c'est par ici :

- ⬇️ **Téléchargement** : [pwn-stack-vuln-no-nx.zip](https://drive.proton.me/urls/M1BY2DF1GM#feOj5ESBeK6H)
- 🔎 **SHA256 & Analyse Virus Total** : [9a97f084d163129f03ad684bfb6d3532ef4c50668e7a1652f6ff650c9f2e6c06](https://www.virustotal.com/gui/file/9a97f084d163129f03ad684bfb6d3532ef4c50668e7a1652f6ff650c9f2e6c06)
- ⚙️ **Construction et lancement du conteneur** :

```sh
docker build -t pwn-stack-vuln-no-nx .

docker run -it --rm  --cap-add=SYS_PTRACE --security-opt seccomp=unconfined pwn-stack-vuln-no-nx
```

> Lors de ce chapitre, nous vous recommandons fortement **d'utiliser le conteneur Docker** afin d'avoir le **même contexte d'exécution**. Cela vous évitera pas mal de petits problèmes qui peuvent s'accumuler en cours de route.
{: .prompt-warning }

Si vous n'arrivez pas **à lancer le programme**, il se peut que la **libc** 32 bits soit manquante. Dans ce cas, pour les distributions utilisant `apt` et `dpkg`, il est possible d'y remédier avec ces commandes :

```sh
sudo dpkg --add-architecture i386 
sudo apt update
sudo apt install libc6:i386
```

Pour ce qui est des options, nous avons déjà vu précédemment les deux premières. En revanche, la dernière option est nouvelle pour nous :

- `-z execstack` : avec cette option nous faisons en sorte que la **pile soit exécutable**. Cela peut vous paraître bizarre car nous avons vu que la pile avait seulement les droits `rw`. Néanmoins, dans d'anciens programme (avant les années 2000), la pile pouvait avoir les droits `rwx` avant l'introduction de certains [correctifs](https://fr.wikipedia.org/wiki/PaX), notamment le bit [NX](https://fr.wikipedia.org/wiki/NX_Bit)..
- `-m32` : besoin d'expliquer ? RTM 😆 !

![](/assets/images/introduction_au_pwn/pile_exec_bis.png)

> Vous constaterez que l'exploitation de ce challenge s'étale sur **plusieurs chapitres**. L'exploitation de ce type de vulnérabilité est **classique** et n'est pas très compliqué pour quelqu'un qui a déjà de l'expérience en pwn.
> 
> Par contre, lorsque que l'on débute, il y a quelques difficultés qui, si elles sont incomprises, peuvent vous empêcher d'avancer dans l'exploitation d'un programme.
> 
> L'exploitation du programme donc paraître longue mais les différents écueils rencontrés en **valent le détour**. Ils sont généralement présents dans pas mal de challenges de pwn. 
{: .prompt-tip }

## Exploitation

Nous n'allons pas revenir sur la vulnérabilité, c'est la même qu'au précédent chapitre 🙄. Ce qui va changer ici est **la manière dont on va l'exploiter**. Encore une fois, bien que de nos jours la pile ne soit plus exécutable, cette méthode peut être appliquée dès lors que l'on peut allouer de la mémoire exécutable. Ce n'est donc **pas du temps perdu** 🤓.

Allons droit au but et faisons planter notre programme dans **gdb** pour arriver au `ret` avec une **très longue chaîne de caractères**. Comme ce ne sont que les caractères au-delà de l'*offset* `256` qui nous intéressent, nous utilisons un *payload* de la forme `"A"*256+"B"*4+"C"*4 ...`.

> Pitié **n'écrivez pas à la main** de *payload* aussi long 😭, utilisez un terminal python (ou autre) pour générer la chaîne de caractère.
{: .prompt-tip }

On commence en tâtonnant avec `"A"*256 + "C"*4`, puis `"A"*256 + "C"*4 +"D"*4` etc. jusqu'à obtenir un *crash*.

Voici le *payload* qui fait planter le programme pour la première fois : `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCDDDD` et le résultat :

![](/assets/images/introduction_au_pwn/sigsegv_exec_pile.png)

En voyant cela, je reste un peu dubitatif, pas vous ? 

- 😄 **bonne nouvelle** : on arrive bien à contrôler `eip` ;
- 😣 **mauvaise nouvelle** : on ne s'attendait pas à contrôler `eip` avec les caractères `A` car ils sont dans notre *buffer* `prenom` et ne devraient donc pas affecter l'adresse de retour.

Affaire à suivre 🔎 ...
### 🔎 Diagnostique du plantage

Tout d'abord, jetons un œil au code assembleur de la fonction `main` :

![](/assets/images/introduction_au_pwn/disass_main_.png)
#### PIE à deux niveaux

> C'est quoi cette fonction `__x86.get_pc_thunk.bx` ? Je l'ai pas ajoutée dans le `main` moi !
{: .prompt-info }

En fait cette fonction met l'adresse de l'instruction qui suit son appel dans `ebx` (ici : `0x080491a1`). Cela permet ensuite **d'accéder à des données relatives à** `eip`. D'ailleurs, la prochaine instruction ajoute `0x2e5f` à `ebx` qui vaudra *in fine* `0x804c000` : c'est la zone mémoire des données (`rw`). Vous voyez ensuite à l'instruction `0x080491e1` que cela permet de charger la chaîne de caractère `"Bonjour %s !\n"` en utilisant un *offset* négatif pour revenir en arrière (dans la zone mémoire des données en lecture seule).

> Je comprends, mais on a bien compilé notre programme pour qu'il ne soit pas PIE avec `-no-pie`.
{: .prompt-info }

En fait il existe deux options pour avoir un programme non PIE :

- `-no-pie` : option utilisée lors du *linking* (**édition de liens** 🇫🇷) ;
- `-fno-pie` : option utilisée lors de la **compilation**.

Comme `-no-pie` n'agit qu'à partir de l'édition de liens qui est une étape **postérieure** à la compilation, le compilateur ne sait pas à l'avance que le programme qu'il compile sera chargé à une **adresse de base fixe** (en 32 bits à l'adresse `0x8048000`). 

Par conséquent, il ne saura pas ce que vaudra `eip` à chaque instruction. Ainsi, si on compile avec l'option `-fno-pie`, vous verrez que le compilateur partira du principe que le programme sera chargé à l'adresse `0x8048000` et utilisera donc des **adresses absolues** plutôt que des **adresses relatives** (via `ebx` par exemple) :

![](/assets/images/introduction_au_pwn/fno_pie.png)

On constate bien que lorsque l'option `-fno-pie` est ajoutée, le compilateur part du principe que le programme **sera chargé à l'adresse** `0x8048000`. Il peut donc accéder à n'importe quelle variable globale en utilisant une **adresse absolue**.

#### Prologue et épilogue

Revenons au code assembleur du `main`.

Comme vous pouvez le voir, le prologue fait pas mal de choses et **sauvegarde pas mal de registres**. Cela n'est pas un problème en soi, le souci est que lors de l'épilogue, `esp` est chargé à partir de la valeur de `ecx`.

`ecx` est évidemment **stocké dans la pile** avant l'adresse de retour. Ainsi, si on réécrit l'adresse de retour, on aura forcément écrasé `ecx` sur la pile. Par conséquent, on aura écrasé l'ancienne valeur de `esp`.

Contrairement à `ebp`, nous devons **garder une valeur valide** pour `esp` car il sera utilisé premièrement pour **récupérer l'adresse de retour**, mais aussi pour **stocker** et **charger** certaines valeurs entre les registres et la mémoire. Autant dire que si `esp` vaut `0x42424242`, on est mal barrés 🤕 !

> On peut pas lui donner simplement une adresse valide comme `0x8048000` ?
{: .prompt-info }

En fait, si on écrase `esp` il faut s'assurer de **deux choses** :

1. l'adresse est située dans une zone mémoire où il est possible de **lire et écrire** ;
2. **on contrôle** la zone mémoire autour de cette adresse.

Vous remarquerez d'ailleurs que lors que notre programme a planté, `eip` a été contrôlé tout en ayant une valeur correcte pour `esp`. Comment cela est-il possible après avoir expliqué plus haut que " écraser l’**adresse de retour** == écraser `esp` " ?

En fait notre *payload* n'a pas totalement écrasé la valeur sauvegardée de `ecx`, voici ce qui s'est passé une fois arrivé à l'adresse `0x80491f8` :

![](/assets/images/introduction_au_pwn/before_pop_ecx.png)
> Pourquoi il y a un octet nul dans l'ancienne valeur de `ecx` alors que notre *payload* n'en contenait pas ?
{: .prompt-info }

Certes, notre *payload* ne contenait pas d'octet nul. En revanche, vu qu'il a été **saisi à la main** (en faisant un copier-coller), on a aussi dû appuyer sur `Entrée` pour envoyer le *payload*. Or le fait de saisir `Entrée` **ajoute un saut de ligne**.

Cette explication n'a pas l'air de nous avancer davantage car on a, au final, un **octet nul** et **non pas** `\n` dans l'octet de poids faible de l'ancienne valeur de `ecx`. Allons à la recherche d'explications dans le manuel de `gets`. Une ligne attire notre attention :

```
gets()  reads  a  line from stdin into the buffer pointed to by s until either a terminating newline or EOF, which it replaces with a null byte ('\0').
```

La fonction, `gets` lit notre entrée utilisateur jusqu'à ce que `\n` soit envoyé dans `stdin`. Une fois que que `\n` est saisi, la chaîne de caractère lue est envoyée. Enfin, elle n'est pas envoyée telle quelle : le **saut de ligne** `\n` est **remplacé par un octet nul** `\x00`, d'où la valeur modifiée de `ecx`.

> Il y a **deux points essentiels** à retenir de ce que nous venons de voir :
> 
> La **première** est qu'il peut y avoir des **effets de bord** dans un programme ou une fonction qui impliquent parfois une vulnérabilité. Il faut donc toujours se poser la question, lors de l'analyse du programme, "qu'est-ce qui pourrait mal se passer ?". Vous ne pouvez pas imaginer le **nombre d'effets de bord** que l'on peut utiliser dans des fonctions comme `printf`, `malloc`, `scanf` etc. 
> 
> **Deuxièmement**, nous venons de découvrir **une technique** pour contrôler un registre sans avoir à écraser totalement sa valeur **en écrasant seulement l'octet de poids faible**. Gardez cette astuce en tête car cela est très utile dans les **programmes PIE** où l'on ne sait pas à quelle adresse est chargé le programme.
{: .prompt-tip }

Pour en revenir à nos moutons 🐑, lorsque l'on a utilisé le *payload* : `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCDDDD`, nous avons constaté que `eip` avait, lors du plantage, la valeur `0x41414141`.

Ce qu'il s'est passé est que la valeur sauvegardée de `ecx` était, par exemple, de `0xffffc7c0`. Or, lorsque l'on écrase l'octet de poids faible avec un octet nul, cette adresse devient `0xffffc700`.  Il y a donc un **décalage** de `0xc0` octets entre l'**ancienne adresse** et la **nouvelle**.

De plus, comme `esp` est chargé à partir de `ecx` par l'instruction `lea    esp, [ecx - 4]`, cela est équivalent à faire `sub esp, 0xc0` (car le décalage est de `0xc0` octets). C'est pourquoi on est "revenus en arrière" dans notre *buffer* `prenom` et que lors du `ret`, `eip` a pris la valeur `"AAAA"`.

Je sais que ça peut paraître un peu technique en lisant cela de prime abord. Essayez de **relire** l'explication à tête reposée en **faisant des schémas** et en regardant ce que cela donne dans **gdb** de votre côté afin que cela vous paraisse **plus clair**. 

#### Comment exploiter tout ça ?

Normalement, si vous avez bien compris ce dont on a parlé précédemment, vous devriez avoir compris qu'il y a **deux manières** d'exploiter ce programme :

1. **méthode rapide** : écraser l'octet de poids faible de `ecx` sur la pile avec `0x00` ;
2. **méthode avancée** : écraser l'adresse de retour ainsi que tous les registres sauvegardés au passage.

Laquelle de ces deux méthodes est la plus simple ? Cela va dépendre du contexte.

Si l'**ASLR est activée**, alors la **première méthode** sera plus intéressante car on aura pas à deviner la valeur de `esp` vu que l'on ne modifie seulement l'octet de poids faible.

Si **l'ASLR est désactivée**, alors la **seconde méthode** est plus intéressante car on connaîtra à l'avance la valeur de `esp`, on pourra donc la restaurer ou la modifier comme bon nous semble.

Comme l'**ASLR** n'a été réellement supportée par Linux qu'[à partir de 2005](https://fr.wikipedia.org/wiki/Address_space_layout_randomization), nous allons faire comme si on exploitait un **vieux programme**. Une fois que la manière d'exploiter un programme sans **ASLR** est comprise, nous pourrons ajouter de plus en plus de protections.

### ASLR

On en a parlé maintes fois sans rentrer dans les détails du fonctionnement de cette protection. Voyons comment cela fonctionne.

L'**ASLR** (*Address space layout randomization*) est une protection permettant **d'aléatoiriser certaines adresses mémoire**. Cela permet de rendre plus compliquée l'exploitation d'un programme car **on ne sait pas à l'avance** où sera chargée la pile, les instructions et les données (quand PIE est activée) ...

Dans **gdb**, activons l'ASLR avec `aslr on` puis relançons le programme afin qu'il s'arrête au début de `main`.

> En désactivant **l'ASLR dans gdb**, cela ne **désactive pas** l'ASLR entièrement dans l'OS. Cela permet seulement de dire à **gdb** : "les prochaines fois que tu charges mon programme, fais en sorte que les zones mémoires soient chargées à **des adresses fixes**".
> 
> Quand l'ASLR est désactivée pour un programme, il devient **plus simple de le déboguer**.
{: .prompt-warning }

Par défaut, l'ASLR est désactivée dans **pwndbg**, en la réactivant, lançons **deux fois** notre programme afin de **comparer** leurs *mappings* mémoire :

![](/assets/images/introduction_au_pwn/compare_aslr_libs.png)

Nous constatons que : 

- certaines zones mémoires sont *mappées* **aux mêmes adresses** : il s'agit de notre programme que l'on a compilé **sans activer PIE** ;
- d'autres sont *mappées* à des adresses différentes d'une exécution à une autre, c'est le principe de l'**ASLR**. Parmi ces zones mémoires, il y a : la **libc**, **ld**, la **pile** etc.

Autre **point intéressant** pour les plus curieux, affichons l'adresse de la fonction `system` lors de deux exécution successives :

1. `0xeb036170` ;
2. `0xf4f4f170`.

On remarque que `system` est effectivement chargé à **deux adresses différentes** mais qui ne sont pas **totalement** différentes : **l'octet de poids faible et le demi-octet** qui le suit sont **les mêmes** (`0x170`). Ce n'est pas une coïncidence !

En réalité les adresses d'un programme ne peuvent pas être **totalement** aléatoires. C'est assez logique : dans un fonction, on ne peut pas avoir une instruction à l'adresse `0xabcdef50` et l'instruction suivante à l'adresse `0x123456f9`. Cela n'aurait pas de sens pour le processeur qui ne saura plus où trouver la prochaine instruction.

Ce qui est réalisé par l'**ASLR** pour les programmes PIE est seulement **un chargement de toute une section** (en l'occurrence celle contenant les instructions) **à une adresse aléatoire**, par exemple :

![](/assets/images/introduction_au_pwn/aslr_exple.png)

De cette manière, nous savons que peu importe l'adresse initiale à laquelle est chargée la section de code, en ajoutant `0xb` à cette adresse on tombera toujours sur l'instruction `mov ebp, esp`.

Cette notion est **cruciale** en *pwn* car c'est ce qui nous permet de ne plus avoir à toujours utiliser **des adresse absolues** dans notre exploit mais plutôt des ***offsets*** (décalages mémoire 🇫🇷). Nous utiliserons très souvent cette astuce dans de prochains chapitres.

### 1️⃣ Contrôler `eip`

**Première étape** dans l'exploitation : 🎯 contrôler `eip`.

Comme nous allons **désactiver l'ASLR** lors de cette exploitation, mettons l'ASLR dans un coin de notre tête et faisons comme si nous en avions jamais parlée. Parmi les deux méthodes susmentionnées, nous allons exploiter ce programme avec **la deuxième** qui nous permet d'avoir **plus de contrôle** sur ce que nous faisons.

> **Astuce gdb** : Il est possible de **désactiver l'ASLR** dans pwndbg avec `aslr off`. Il sera ensuite nécessaire de relancer le programme pour que le changement soit effectif.
> 
> Cela ne désactive l'ASLR **que pour le programme en cours de débogage** et n'a pas d'incidence sur les autres programmes de la machine.
{: .prompt-tip }

Premièrement, il va falloir trouver à partir de quel décalage dans l'entrée nous arrivons à écraser l'adresse de retour.

> C'est très simple ! Il suffit d'augmenter la taille de notre *payload* 4 octets par 4 octets pour voir dans **gdb** à partir de quand on écrase l'adresse de retour 😎.
{: .prompt-info }

C’est très bien d’y avoir pensé ! Mais… c’est une **fausse bonne idée**. Pour rappel, à la fin du `main`, `esp` est chargé à partir de la valeur de `ecx` qui est elle-même écrasée par notre *payload*. Il est donc nécessaire que `ecx` contienne une adresse vers une zone mémoire que nous contrôlons : **la pile**. Enfin, on ne contrôle pas totalement la pile mais on entend par là que l'on **contrôle le contenu d'une partie de la pile**, à savoir le *buffer* `prenom`.

Concernant l’adresse de la pile que nous allons placer dans `ecx` via notre chaîne de caractères, c’est très simple : nous allons **réutiliser celle qui aurait dû s’y trouver** si le programme s’était exécuté normalement.

Pour trouver cette adresse, il suffit de lancer le programme avec une entrée qui **n'écrase pas** `ecx` par exemple : 

```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCC
```

Ensuite, il faut mettre un point d'arrêt à l'adresse `0x80491f8` avant que  `pop ecx` soit exécuté pour voir ce qu'il va falloir utiliser comme adresse pour `ecx` :

![](/assets/images/introduction_au_pwn/ecx_val.png)

> Il se peut que vous ayez une **valeur différente** de celle que j'ai. Par contre, vous devriez avoir la même valeur d'une exécution à une autre étant donné que l'ASLR est désactivée. 
> 
> ⚠️ Prenez bien le temps de récupérer cette valeur et de l'adapter dans les prochains *payloads* afin d'être en mesure de suivre le cours sans soucis.
{: .prompt-tip }

> **Astuce gdb** : il est possible d'utiliser la commande `stack N` pour afficher les `N` premières valeurs de la piles dans un format plus lisible que les commandes classiques.
{: .prompt-tip }

A présent que nous savons quelle valeur doit avoir `ecx`, nous pouvons ajouter `\xc0\xc7\xff\xff` (*little endian* oblige) à notre *payload*. Techniquement, il ne reste plus qu'à écraser les 3 registres restants restaurés (respectivement `ebx`, `edi` et `ebp`) pour atteindre l'adresse de retour. Tentons d'écraser `eip` avec `0xdeadbeef` en utilisant cette nouvelle charge utile :

```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCDDDD\xc0\xc7\xff\xffEEEEFFFFGGGG\xef\xbe\xad\xde
```

Ici l'adresse `\xc0\xc7\xff\xff` est **à adapter** en fonction de ce que vous avez.

> Euh ... comment on censés envoyer des caractères non ASCII dans **gdb**?
{: .prompt-info }

> **Astuce gdb** : En utilisant `run < <(commande)` dans **gdb**, il est possible d'envoyer la même entrée à un programme que si on faisait `commande | ./prgrm` en dehors de **gdb**.
> 
> Si vous avez une erreur du type `/bin/sh: 1: Syntax error: redirection unexpected`, cela est sûrement dû au fait que **gdb** utilise `sh` comme terminal au lieu de `bash`.
> 
> Pour cela, vous pouvez remplacer `sh` par `bash` avec `ln -sf /usr/bin/bash /bin/sh`. ⚠️ Attention, cette commande, sur votre machine, fera en sorte que `/bin/sh` exécute toujours `bash` et ce, définitivement. En revanche, cette commande peut être utilisée **sans soucis dans un conteneur** car le Dockerfile se charge de mettre en place ce lien symbolique. 
{: .prompt-tip }

Pour envoyer un *payload* en utilisant des caractères non ASCII et pour éviter le saut de ligne, on utilise : 

```
run < <(echo -ne 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCDDDD\xc0\xc7\xff\xffEEEEFFFFGGGG\xef\xbe\xad\xde' )
```

#### Du travail, encore du travail

En envoyant ce *payload*, on s'aperçoit que `ecx` a bien la valeur qu'il doit avoir par rapport à une exécution nominale. De plus, on contrôle bien comme convenu `ebx`, `edi` et `ebp`. Par contre, on ne contrôle pas `eip` et le programme termine son exécution **sans soucis** 😓.

Cette fois-ci, nous n'allons pas diagnostiquer en détails pourquoi `eip` n'a pas été écrasé. Voici toutefois quelques indices et pistes de compréhension :

- on se rend compte, dans **gdb**, que `eip` n'est pas situé immédiatement après la valeur sauvegardée de `ebp` mais `0x10` octets plus loin ;
- dans le prologue, `esp` est aligné par l'instruction `and esp, 0xfffffff0`.

A partir de ces informations, vous devriez avoir compris la raison pour laquelle nous avons ce décalage :

![](/assets/images/introduction_au_pwn/diff_de_piles.png)

> Si vous n'avez toujours pas compris la raison de ce décalage, il faut savoir que lorsque l'on est entré dans le `main`, `esp` n'était **pas aligné sur 4 bits** (mais il se peut que dans votre cas, `esp` soit aligné auquel cas vous n'avez pas eu ce décalage).
{: .prompt-tip }

Finalement cela ne change pas grand chose-pour nous si ce n'est que nous devons mettre notre valeur de `eip` quelques *offsets* plus loin dans notre *payload*, plus précisément `0x10` comme nous l'avons vu plus précédemment.

Réessayons avec ce *payload* en mettant `0xdeadbeef` 16 octets plus loin :

```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCDDDD\xc0\xc7\xff\xffEEEEFFFFGGGGHHHHIIIIJJJJKKKK\xef\xbe\xad\xde
```

N'oubliez pas d'adapter l'adresse `\xc0\xc7\xff\xff` si besoin.

En plein de dans le mille 🎯 :

![](/assets/images/introduction_au_pwn/deadbeef_eip.png)

Super ! On contrôle enfin `eip` 😎 !

Contrôler `eip` n'est pas un **but en soi**, néanmoins c'est une étape très souvent **nécessaire** avant de pouvoir **exploiter** pleinement une vulnérabilité. C'est déjà une bonne chose de faite. Cela nous a pris un peu de temps pour y parvenir car il y a eu quelques **notions** et quelques **points** sur lesquels nous devions nous attarder sans quoi, on ne comprendrait pas très bien ce que nous sommes en train de faire.

## 📋 Synthèse

Nous sommes arrivés à notre premier objectif qui est de contrôler `eip`. Notre prochaine étape sera de réaliser une **exécution de code arbitraire**, c'est-à-dire de faire exécuter à notre programme exploité **n'importe quelle instruction assembleur**.

Voici un résumé de ce que nous avons vu et la méthodologie suivie pour contrôler `eip` :

- la fonction `gets` nous permet de réaliser un *buffer overflow* dans la pile, via le *buffer* `prenom` ;
- **deux méthodes** peuvent être utilisées pour contrôler `eip` ;
- l'**ASLR étant désactivée**, nous pouvons même savoir **à l'avance** vers quelles adresses pointe `esp` ;
- un **décalage** est constaté entre la valeur sauvegardée de `ebp` et l'adresse de retour en raison du non alignement de `esp` ;
- en prenant en compte ce décalage, on réussit **à modifier l'adresse de retour**.