---
title: Partie 1 - Introduction
date: 2023-09-02 10:00:00
categories: [Reverse, Introduction à l'exécution symbolique avec angr]
tags: [angr, Exécution symbolique]     # TAG names should always be lowercase
author: kabeche
toc: true
---
# Introduction

angr est un **moteur d'exécution symbolique** *open source* qui permet d'analyser et d'émuler des programmes binaires. Il utilise l'exécution symbolique pour explorer toutes les branches d'exécution possibles d'un programme. Il permet, entre autres, de découvrir les vulnérabilités, les bugs et conditions qui permettent d'atteindre certaines parties d'un programme.

L'un des principaux avantages d'angr est sa capacité à analyser les programmes **sans avoir besoin de les exécuter réellement**. Cela permet d'éviter les problèmes de sécurité (exemple : *malware*) et d'analyser plus facilement un bout de code sans avoir à l'exécuter. 

angr est utilisé dans de nombreux domaines de la sécurité informatique, tels que la recherche de bugs, l'analyse de *malware*, la sécurité des systèmes embarqués et dans les challenges !

Il est compatible avec de nombreuses architectures de processeurs et prend en charge de nombreux formats de fichiers binaires.

Ah oui au fait, en termes de **prononciation** :

![angueur_pas_angr](/assets/images/introduction_a_l_execution_symbolique_avec_angr/leviosa.gif)


## Les différents types d'analyse

Avant de nous intéresser directement à l'exécution symbolique, voyons d'abord quelles sont les deux principales méthodes utilisées pour analyser un programme.

Le programme utilisé en guise d'exemple est le suivant :

```c++
#include <stdlib.h>

int main(int argc, char *argv[]) 
{
    int arg = atoi(argv[1]);

    if (arg == 0xdeadbeef) 
    {
        return 1337;
    } 
    else 
    {
        return -1;
    }
}

```

### L'analyse statique

Ce type d'analyse est qualifié de "**statique**" car il ne nécessite **pas l'exécution** du programme. Généralement, on se sert d'outils qui permettent d'extraire des informations d'un programme et de le comprendre.

On peut se servir d'un **désassembleur** afin de convertir des données brutes d'octets en instructions assembleur, exemple :  **objdump**, **radare2**, **capstone**.

Exemple du précédent code désassemblé (après compilation) :

![](/assets/images/introduction_a_l_execution_symbolique_avec_angr/screen/disassm.png)

On se sert également de **décompilateurs** afin d'avoir des informations supplémentaires, telles que du code, plus facilement lisible pour un humain. On peut citer, par exemple : **Ida Pro**, **Ghidra**, **Binary Ninja**, **Cutter** ...

Exemple du précédent code décompilé :

![](/assets/images/introduction_a_l_execution_symbolique_avec_angr/screen/decompiled.png)

En utilisant ces divers outils il est, souvent, déjà possible de comprendre ce que fait un programme, comment sont appelées ses diverses fonctions et comment elle interagissent entre elles.

### L'analyse dynamique

Contrairement à l'analyse statique, l'analyse dynamique **nécessite l'exécution** du programme. Cette exécution peut être réalisée sur une machine physique, un émulateur (Qemu par exemple), une machine virtuelle ...

Divers outils, appelés **debuggers**, permettant de réaliser une analyse dynamique en exécutant pas à pas un programme. Par exemple : **GDB**, **windbg**, **x64dbg** ...

Exemple de l'exécution de la fonction `main` dans GDB :

![](/assets/images/introduction_a_l_execution_symbolique_avec_angr/screen/gdb.png)

Ce type d'analyse permet généralement de confirmer ce qui a été vu en analyse statique ou de comprendre certaines fonctionnalités qui n'ont pas pu être analysées correctement.

Par exemple, les *malwares* les plus robustes disposent souvent de plusieurs couches d'**obfuscation** qui ne ralentissent et limitent la compréhension de leur fonctionnement en analyse statique.

Par exemple, certaines fonctions auront un code **décompilé illisible**. Dans d'autres cas il peut arriver de ne pas du tout pouvoir décompiler le code assembleur du programme.

Ainsi, l'objectif de l'analyse dynamique est de **reproduire l'environnement d'exécution** du programme étudié afin d'analyser au mieux son comportement à travers l'analyse de son exécution. Il ne s'agit pas seulement d'utiliser un debugger, mais également d'autres **outils de monitoring** afin d'observer les processus créés, les fichiers modifiés, les évènements déclenchés...

En reverse, on ne choisit pas soit d'utiliser l'analyse statique soit d'utiliser l'analyse dynamique. Au contraire, on préfère généralement **combiner les deux** et tirer profit des avantages de chacune d'elles.

## L'exécution symbolique

L'exécution symbolique est généralement moins connue et moins maîtrisée du grand publique. Afin de comprendre son fonctionnement et son utilité, reprenons le précédent programme :

```c++
#include "stdlib.h"

int main(int argc, char *argv[]) 
{
    int arg = atoi(argv[1]);

    if (arg == 0xdeadbeef) 
    {
        return 1337;
    } 
    else 
    {
        return -1;
    }
}
```

Le fonctionnement du programme est assez trivial : le programme récupère le premier paramètre saisi par l'utilisateur et le compare à `0xdeadbeef`.

Si les valeurs sont identiques, la valeur retournée est `1337`, sinon c'est `-1`. A ce stade, l'analyse statique nous permet d'ores et déjà de trouver la bonne valeur à saisir. Essayons tout de même de trouver le bon input afin que la valeur de retour soit `1337` grâce à angr.

Tout d'abord, créez un fichier "exemple_1.c" contenant le précédent programme. Puis compilez le avec la commande : `gcc -no-pie exemple_1.c -o exemple_1`.

> L'option `-no-pie` implique que les **instructions du programme** sera toujours chargé à la même adresse et ne sera pas (totalement) soumis à l'**ASLR**. De cette manière angr ne nous demandera pas de lui spécifier une adresse de base, ce qui est plus commode pour nous.
{: .prompt-tip }

Ouvrons le programme fraîchement compilé `exemple_1` avec IDA (IDA Free fera l'affaire ;) ) :

![](/assets/images/introduction_a_l_execution_symbolique_avec_angr/screen/disassm_paths.png)

Finalement rien de surprenant, on retrouve bien les deux blocs de code, l'un lorsque la comparaison est **réussie** (en **vert**) l'autre lorsque la comparaison **échoue** (en **rouge**).

Avant d'aller plus loin, il est nécessaire de se familiariser avec quelques **notions cruciales** lorsque l'on aborde l'exécution symbolique.

### Les états

La notion d'**état** en exécution symbolique est une notion très importante. En comprenant comment fonctionne la gestion des états, on comprend comment fonctionne l'exécution symbolique. De la même manière, une gestion désastreuse des états limite fortement la puissance que l'on peut tirer de l'exécution symbolique.

Un **état** en exécution symbolique **est le contexte dans lequel est actuellement exécuté le programme**. Un contexte est donc totalement déterminé par la valeur qu'ont ses registres et les différentes zones mémoire assignées. Ainsi, **deux états** sont différents **si et seulement si** il ont au moins un registre, une zone qui a une valeur différente ou des variables qui ont des contraintes différentes. 

Un état est un peu comme ce qui est affiché dans le précédent *screenshot* de **gdb** dans la section "Analyse dynamique" avec les différentes valeurs des registres, de la mémoire ...

angr **subdivise** l'état courant quand il rencontre un **branchement** vers deux chemins différents qui ont chacun leur contrainte. Par exemple,  lorsque notre état initial arrivera à l'instruction `0x40114E : jnz     0x401157`, deux cas sont possibles :

- Soit `[rbp+var_4] == 0xDEADBEEF`
- Soit `[rbp+var_4] != 0xDEADBEEF`

> Il est possible que les **adresses** utilisées dans ce tutoriel ne soient **pas en adéquation** avec le programme "exemple_1" si vous l'avez compilé sur votre machine. 
> 
> Il suffit d'adapter le script en modifiant les différentes adresse à partir des captures d'écran de ce tutoriel pour que cela **corresponde aux adresses** utilisées par votre programme.
{: .prompt-warning }

Ainsi, il y a une contrainte sur la valeur contenue à `[rbp+var_4]` qui est différente en fonction du chemin parcouru. Que va faire angr dans ce cas ? C'est très simple. Il va prendre l'état initial `state_0` et réaliser deux "copies" de cet état, nommons les `state_vert` et `state_rouge`.

Les deux différences entre `state_vert` et `state_rouge` sont les suivantes :

- `state_vert` : 
	- Le registre `RIP` vaut `0x401150`
	- L'état a la contrainte : `[rbp+var_4] == 0xDEADBEEF`
- `state_rouge` : 
	- Le registre `RIP` vaut `0x401157`
	- L'état a la contrainte : `[rbp+var_4] != 0xDEADBEEF`

Au-delà de ces deux différences, les autres registres et zones mémoire de ces deux sous-états sont les mêmes. La gestion de **plusieurs états** simultanément est ce qui fait la **force de l'exécution symbolique** car cela permet de parcourir bien plus de code qu'avec une simple exécution du programme.

Paradoxalement, la **subdivision** en plusieurs états est également ce qui fait la **faiblesse** de l'exécution symbolique : plus il y a de branchements dans un programme, plus il y a d'états à gérer, plus cela **consomme de la RAM**. Ainsi, dans un programme qui effectue un grand nombre de boucles ou qui contient des boucles dans des boucles, la mémoire vive peut vite saturer et faire planter l'exécution symbolique. Nous ferons par la suite un exemple de programme qui provoque une **explosion de chemins**.

Voici grossomodo le contenu des trois précédents états :

![](/assets/images/introduction_a_l_execution_symbolique_avec_angr/screen/chemin_div.png)

> Mais la contrainte portait sur `[rbp+var_4]` pourquoi est-elle maintenant sur `eax_val`.
{: .prompt-info }

Certes la contrainte porte sur la valeur contenu à `[rbp+var_4]`, mais quelle variable est à l'origine de `[rbp+var_4]` ?

Si on regarde quelques instructions plus haut, on voit : `0x401144 : mov     [rbp+var_4], eax` où `eax` est la valeur de retour de `atoi`. Ainsi, mettre une contrainte sur `[rbp+var_4]` revient à mettre une contrainte sur le contenu de `eax` à la sortie de `atoi` que l'on nomme `eax_val`.

`eax_val` est une **variable symbolique** et c'est sur elle que sera établie la contrainte.

### Les variables symboliques

Une autre **notion importante** en exécution symbolique est la notion de **variables symboliques**. En fait, pour qu'un moteur d'exécution symbolique puisse parcourir plusieurs chemins via plusieurs états simultanément, il faut que certaines variables soient symboliques.

Contrairement aux variables ayant des **valeurs concrètes**, les variables symboliques peuvent, au départ, avoir n'importe quelle valeur. Ce n'est qu'au fur et à mesure de l'exécution du programme, du choix du chemin lors de branchements `if / else` que des contraintes seront ajoutées à la variable symbolique.

Imaginons que `eax_val` ait une **valeur concrète** au retour de `atoi`, par exemple `0xcafebabe`. Il ne sera pas possible d'imposer des contraintes sur `eax_val` car la variable a déjà la contrainte suivante `eax_val == 0xcafebabe`.

Ainsi, initialement, **une variable symbolique peut avoir n'importe quelle valeur** selon son type.

Par exemple :
- une variable de 8 bits aura une valeur initialement comprise entre 0x00 et 0xff (255)
- une variable de 32 bits aura une valeur initialement comprise entre 0x00 et 0xffffffff (4294967295)

#### Contraintes d'une variable symbolique

Généralement, une variable symbolique va **subir plusieurs contraintes** au fil de l'exécution et du chemin emprunté par le moteur d'exécution symbolique. Il existe alors **trois cas** possibles pour cette variable une fois l'exécution stoppée après avoir suivi un certain chemin :

- Il y a une **unique solution** : Au vu des contraintes sur la variable, il ne peut y avoir qu'une unique solution valable.  
- Il y a **plusieurs solutions** possibles : Par exemple, le chemin suivi ne peut être parcouru que si la taille de la chaîne de caractères ( qui est une valeur symbolique ) est strictement positive.
- Il n'y a **aucune solution** possible : Cela peut arriver lorsque plusieurs contraintes ne sont pas satisfaisables en même temps. Par exemple si une des contraintes est  `var >= 10` et l'autre est `var < 8`, il n'existe pas de solution possible.

En fait, angr ne détermine pas tout seul si, au moins une ou plusieurs solutions sont possibles. Il s'aide de ce que l'on appelle un **SMT solveur**.  Il s'agit d'un **outil** qui prend en entrée un ensemble de **formules logiques** qui spécifient des contraintes sur des variables et retourne un résultat, si cela est possible.

> Ce n'est pas parce qu'un problème est satisfaisable que le solveur retournera **facilement** une solution. Certaines contraintes sur une variable peuvent être tellement **lourdes** et **complexes** que cela prendra des minutes voire des heures avant de trouver un résultat.
{: .prompt-warning }

Parmi les SMT solveurs les plus connus il y a : **Z3, Boolector, Bitwuzla** ...

Quant à angr, il utilise **Z3** en tant que solveur.

#### Le SMT solveur Z3

Un solveur SMT (Satisfiability Modulo Theories), tel que Z3, est un outil logiciel qui permet de **résoudre des problèmes de satisfiabilité**. Il est utilisé pour vérifier si une certaine  formules logique disposant de combinaisons de contraintes est **satisfaisable ou non**.

Ce qui est encore plus impressionnant avec un solveur est que, lorsqu'il existe au moins une solution, il arrive souvent à nous retourner une solution. Dans les cas où la formule est vraiment très compliquée et que la machine utilisée n'est pas très puissante, il se peut qu'il y ait un **timeout** sans trouver de solution.

Prenons un exemple concret dans lequel nous allons demander à z3 de résoudre deux équations :
- Une ayant **plusieurs solutions possibles**
- Une n'ayant **aucune solution** 

```python
from z3 import *

# Création de la variable x
x = Int('x')
# Création de l'équation
equation = x - 7 >= 2
# Création du solveur Z3
solveur = Solver()
# Ajout de l'équation au solveur
solveur.add(equation)

# Résolution du solveur
if solveur.check() == sat:
	# Si une solution est trouvée, affiche la valeur de x qui satisfait l'équation
	modele = solveur.model()
	solution = modele[x]
	print("Une solution de l'équation est : x =", solution)

else:
	# Si aucune solution n'est trouvée
	print("Pas de solution trouvée.")
```

En exécutant ce script python, une sortie que l'on peut avoir est `Une solution de l'équation est : x = 9` qui est bien une solution de l'équation `x - 7 >= 2` (où x est un entier).

Maintenant, ajoutons une autre contrainte avec les deux lignes suivantes en dessous de `solveur = Solver()` :
```python
equation_2 = x < 0
solveur.add(equation_2)
```

Les contraintes sur `x` n'étant pas satisfaisables, l'exécution du script retourne `Pas de solution trouvée.`.
L'idée n'étant pas de savoir utiliser de **manière avancée** z3 (angr le fera pour nous ;) ) mais de comprendre à quoi sert un solveur et comment les utiliser.

### Utilisation d'angr

Nous avons parlé des principaux éléments théoriques liés à l'exécution symbolique (variable symbolique, état, contraintes, solveur ...). Passons à la partie pratique avec cet exemple.

L'idée globale est de demander à angr d'exécuter la fonction `main` et de passer par le bloc vert afin qu'il nous donne le bon input pour y arriver.

Voici le début du script qui utilise angr nous permettant de réaliser ça (j'utilise les **mêmes adresses** que celles que l'on a vu précédemment) :

```python
import angr

p = angr.Project("./exemple_1")
state_0 = p.factory.blank_state(addr= 0x401122)

sm = p.factory.simulation_manager(state_0)

print("[+] Exploration en Cours ....")
sm.explore( find = 0x401150, avoid = 0x401157)
```

Décortiquons ensemble ce script :

1. `p = angr.Project("./exemple_1")` permet de créer un projet "angr" en spécifiant le programme que l'on souhaite utiliser
2. `state_0 = p.factory.blank_state(addr= 0x401122)` : on crée un état initial "vide" qui démarre à la première instruction du `main` à l'adresse `0x401122`. 
3. Une fois que notre état initial `state_0` est créé, il va falloir créer le **simulation_manager**. Il s'agit d'un objet qui va gérer tous les états lors de l'exécution symbolique. Au départ, il n'y a qu'un seul état, celui que l'on vient de créer. Toutefois, lorsque angr va rencontrer des branchement, par exemple lors d'un "if-else", il va "subdiviser" l'état courant en deux "sous-états" où chacun prendra respectivement le chemin du "if" et du "else".
4. Ensuite, on demande au **simulation_manager** d'atteindre le bloc "vert" ( la comparaison avec `0xdeadbeef` est réussie) en spécifiant `find` et d'éviter le bloc en rouge ( la comparaison a échoué) en spécifiant `avoid`.

#### Le Simulation Manager

C'est ce gros "truc" qui va **gérer tous nos états** lors de l'exécution symbolique. A un instant T de l'exécution symbolique, les états peuvent avoir différents **statuts** :

1. **active** : Un état actif représente un chemin d'exécution en cours d'exploration par angr. Cela signifie qu'angr est en train d'exécuter (symboliquement) des instructions pour ce chemin spécifique ;
3. **inactive** : Un état inactif est un chemin d'exécution qui a été entièrement exploré. Cela peut se produire lorsque toutes les instructions du programme ont été suivies pour ce chemin spécifique ou qu'il s'agit d'une destination atteinte ; angr n'a plus besoin de le considérer ;
3. **found** : Lorsqu'angr atteint un état "found" , cela signifie que le chemin d'exécution satisfait une condition spécifique définie par l'utilisateur. Par exemple, cela peut être le cas lorsque le programme atteint une certaine adresse, quand il atteint une fonction spécifique ou lorsqu'une autre condition définie est satisfaite ;
4. **avoid** : De la même manière qu'un état **found** signifie qu'on a atteint du code dont le contexte satisfait certaines conditions, un état **avoid** est un état dans lequel on souhaite que l'exécution du programme soit stoppée ;
5. **unsat** : Un état "unsat" (insatisfaisable) est un chemin d'exécution qui mène à une contradiction ou à une condition impossible à satisfaire. Cela se produit généralement lorsqu'une condition de programme invalide est rencontrée, ce qui signifie qu'angr ne peut pas explorer ce chemin d'exécution plus loin.

Voici un exemple dans lequel le SM (Simulation Manager) contient seulement deux états :
- un état de type **found**
- un état de type **avoid** 

![](/assets/images/introduction_a_l_execution_symbolique_avec_angr/found_avoid.png)

#### Première exécution du script

On exécute le script avec `python3 angr_explore.py` et là, et bien rien ! Le script ne semble pas faire grand chose ... 
Vous constaterez qu'angr n'est pas très content et vous le fait savoir via plusieurs *warnings*. Certains sont **anodins** (et nous verrons plus tard pourquoi) mais il y en a un qui revient souvent et nous permet de comprendre pourquoi le script ne fait pas grand-chose.

Il s'agit de ce *warning* : 
```
WARNING | angr.storage.memory_mixins.default_filler_mixin | Filling memory at 0xfffffffffffffc0b with 1 unconstrained bytes referenced from 0x539  
fa0 (atoi+0x0 in libc.so.6 (0x39fa0))
```
Bon ça a l'air d'être du gros charabia pour nous mais essayons quand même de comprendre la logique dans tout ça. En tout cas, de ce que l'on voit, c'est qu'il semble y avoir **un petit soucis** à cette adresse : `(atoi+0x0 in libc.so.6 (0x39fa0))`.

Dès les premières instructions de la fonction `atoi`, angr est dans les choux. Ce qui est en réalité normal. En effet, `atoi` est une fonction importée. Elle est donc exécutée dynamiquement par le programme en faisant appel à la bibliothèque standard `libc`.

Comme angr n'exécute rien dynamiquement, il ne charge même pas la libc au démarrage de l'application. Nous allons donc devoir gérer l'appel à `atoi` afin de ne plus être embêté par la suite.

> En réalité angr gère plutôt bien certaines fonctions de base de la libc. Mais il vaut mieux parfois prendre les rênes afin de savoir exactement ce qui est réalisé.
{: .prompt-tip }

#### Ajout d'un hook

Il existe différentes manières de gérer soi-même ou de contourner l'appel à une fonction (ou une instruction de manière générale). La plus simple est l'utilisation de *hooks*, c'est celle que nous allons utiliser. Il existe une autre manière plus avancée de faire des *hooks* via `SimProcedure` (cf les [SimProcedures](https://docs.angr.io/en/latest/extending-angr/simprocedures.html)).

Voici comment implémenter un *hook* dans angr :

```python
import angr

def hook_atoi(state):
	# Faire des trucs
	return

p = angr.Project("./exemple_1")
# Ne pas oublier d'adapter en fonction de vos adresses
state_0 = p.factory.blank_state(addr= 0x401122)

sm = p.factory.simulation_manager(state_0)
p.hook(0x40113f, hook_atoi,5)

print("[+] Exploration en Cours ....")
sm.explore( find = 0x401150, avoid = 0x401157)
```

Cela se déroule en deux étapes :

1. Appeler la fonction `hook` de angr sur le projet avec trois arguments :
	- L'adresse de l'instruction dont on veut intercepter ou modifier le fonctionnement
	- la fonction python qui sera exécutée à la place
	- la taille totale de l'instruction (ou des instructions) à *hook*, ici, 5 octets :
	![](/assets/images/introduction_a_l_execution_symbolique_avec_angr/Pasted image 20230626140739.png)
2. Définir la fonction qui sera appelée lors du *hook*. En fonction des instructions ou fonctions *hookées*, son contenu ne sera pas le même. Par exemple, si on *hook* la fonction `printf`, la fonction de *hook* pourrait simplement afficher une chaîne de caractères à l'écran avec `print` en python.

![](/assets/images/introduction_a_l_execution_symbolique_avec_angr/hook.png)

Dans le code exécuté, angr va agir de la sorte :

1. En arrivant à l'adresse `0x40113f`, il se rend compte que 5 octets à partir de cette adresse doivent être *hookés* et qu'ils seront donc gérés par notre script. Cela correspond exactement à l'instruction `call _atoi`
2. Le hook Python `hook_atoi` est alors exécuté au lieu de l'instruction
3. Une fois la fonction `hook_atoi` terminée, angr reprend l'exécution symbolique à partir de 5 octets plus loin

Ce qui est intéressant avec les fonctions de *hook* est qu'elles peuvent disposer, en paramètre, de l'**état** (ici `state`) **courant** lorsque le *hook* a été déclenché. Cela est énormément pratique pour **consulter la valeur des registres**, les **modifier**, **inspecter la mémoire**, la *stack* etc.

Pour l'instant, la fonction de hook est vide, elle ne fait rien. Remplissons-là ! 

On sait que la fonction `atoi` convertit une chaîne de caractères en un entier. Ce que l'on aurait pu faire pour garder le même fonctionnement de `atoi` est d'utiliser la variable `argv` de Python pour retourner un entier arbitraire, choisi au moment du lancement du script.

Mais ce n'est pas ce que nous allons faire. Rappelons nous de l'objectif que nous souhaitons atteindre grâce à l'exécution symbolique : **Trouver le bon argument à donner au programme pour qu'il retourne 1337**.

#### Utilisation d'une variable symbolique

Ainsi notre argument `argv[1]` ne doit pas être concret mais **symbolique**. Nous devons mettre la valeur de retour dans le registre `rax` étant donné que c'est le registre qui contient la valeur retournée par une fonction en x86_64.

```python
import angr
import claripy

# Variable symbolique de 64 bits
arg_symb = claripy.BVS('argv', 8*8)

def hook_atoi(state):
	print("[i] La fonction atoi a été hookée")
	# On retourne la variable symbolique via rax
	state.regs.rax = arg_symb
	
p = angr.Project("./exemple_1")
state_0 = p.factory.blank_state(addr= 0x401122)

sm = p.factory.simulation_manager(state_0)
p.hook(0x40113f, hook_atoi,5)

print("[+] Exploration en Cours ....")
sm.explore( find = 0x401150, avoid = 0x401157)
print("[+] Arrivé à destination")

print("[+] Chemins explorés : ",sm)
```

En exécutant cette version du script, on obtient après quelques *warnings* :
```
[i] La fonction atoi a été hookée  
[+] Arrivé à destination  
[+] Chemins explorés :  <SimulationManager with 1 found, 1 avoid>
```
Tout s'est bien passé comme prévu et angr a pu parcourir deux chemins au total :

- `found` qui regroupe les états issus des chemins parcourus qui ont pu atteindre l'objectif fixé, ici : `0x401150` (il peut y avoir plusieurs `found`, dans notre cas, il n'y en a qu'un)
- `avoid` qui regroupe les états issus des chemins parcourus et qui doivent s'arrêter s'ils rencontrent une adresse de type `avoid`, ici : `0x401157` (dans notre cas, il n'y en a qu'un)

Voyons ensemble quelques explications quant à la variable symbolique `arg_symb`. Tout d'abord nous avons importé le module `claripy` qui est un module qu'utilise angr pour gérer les variables **symboliques** et **concrètes** ainsi que l'utilisation du solveur **z3**. 

Les deux types de variables peuvent être déclarés de cette manière :
- **Les variables concrètes** (ex : `var = claripy.BVV(0xdeadbeef, 8*4)`) : pour déclarer une variable concrète, deux arguments sont à renseigner : 
	1. Sa valeur
	2. Sa taille ( **en bits ! et non en octets, attention !** ),  dans cet exemple, la variable est de 32 bits ( 4 octets )
- **Les variables symboliques** (ex : `var_symb = claripy.BVS('x', 8)`): pour déclarer une variable symbolique, deux arguments sont également à renseigner :
	1. Le nom de la variable symbolique 
	2. Sa taille (ici 1 octet, utile pour représenter, par exemple, une variable de type `char`)

> J'insiste : la taille spécifiée lors de la création de variables symboliques `BVS` ou concrètes `BVV` avec claripy est en **BITS** ! 
{: .prompt-warning }

Ici la variable symbolique que nous utilisons est désignée par `arg_symb` ( ou `argv` du point de vue de claripy) et elle a une taille de 8 octets (64 bits). Nous l'utilisons lors du *hook* de `atoi` afin de la retourner ( via `rax`).

Désormais, angr sait que la valeur de retour est symbolique, la comparaison avec `0xdeadbeef` peut ainsi échouer ou réussir ici :

![](/assets/images/introduction_a_l_execution_symbolique_avec_angr/Pasted image 20230626165103.png)

> Si on voulait optimiser le script, on aurait pu seulement retourner une valeur de 32 bits via `eax` étant donné que seule les 4 premiers octets de `rax` sont utilisés pour la comparaison.
{: .prompt-tip }

> Mais attends, tu nous as pas dit pourquoi il y a un 36000 mille messages de *warning* ?
{: .prompt-info }

En fait les différents *warnings* que l'on a pas traités concernent des zones mémoire que nous n'avons pas initialisées et qui sont manipulées par le programme. Par exemple, les premières instructions de la fonction `main` sont :
```asm
0000000000401122   push    rbp
0000000000401123   mov     rbp, rsp
```

Ainsi, dès la première instruction, angr (qui exécute symboliquement les instructions) doit effectuer `push rbp`. 

Ainsi, deux choses sont à réaliser :

1. Récupérer la valeur de `rbp`
2. La mettre sur la *stack*

Le soucis est qu'angr ne sait pas ce que vaut `rbp` ni à quelle zone mémoire est la *stack*. En effet, nous n'avons spécifié aucune de ces valeurs, elles sont donc considérées comme **non contraintes** par défaut  !

Ce que fait angr en nous affichant un message de ce type :
```
WARNING | Filling register rbp with 8 unconstrained bytes referenced from 0x401122 (main+0x0 in exemple_1 (0x401122))
```
est qu'il "remplit" `rbp` avec des valeurs **sans contraintes** afin qu'il puisse "exécuter" l’instruction `push rbp` en ayant une valeur (quelconque) à mettre dans la *stack*. Idem pour l'adresse de la *stack*.

Si on voulait absolument donner une valeur à `rsp` et `rbp`, on pourrait faire quelque chose de la sorte :
```python
state_0 = p.factory.blank_state(addr= 0x401122)
state_0.regs.rsp = 0x7fffff0000
state_0.regs.rbp = 0x7fffff0008
```

Cela peut être utile lorsque l'on veut absolument avoir les mêmes adresses mémoire que celles qui sont affichées par un *debugger* lorsque l'on réalise une analyse / exécution dynamique.

#### Récupération de l'entrée valide

On a pu faire en sorte qu'angr **atteigne** l'adresse du bloc où la comparaison est réalisée correctement. Néanmoins, angr ne nous as pas dit avec quelle entrée valide il a pu en arriver là. Je vous rassure, on y est presque !

Pour rappel, le simulation manager `sm` a pu avoir au moins un état `found`. Il suffit désormais de :

- se placer (ou *switcher*) dans le contexte de l'état qui est arrivé dans le bloc "en vert" ( il s'agit du seul état présent dans `sm.found`)
- faire appel au solveur afin qu'il nous retourne une valeur de `arg_symb` qui a permis à cet état d'arriver dans le bloc qui nous intéresse
- afficher ladite valeur !

Voici le script final :
```python
import angr
import claripy

# Variable symbolique de 64 bits
arg_symb = claripy.BVS('argv[1]', 8*8)

def hook_atoi(state):
	print("[i] La fonction atoi a été hookée")
	# On retourne la variable symbolique via rax
	state.regs.rax = arg_symb

p = angr.Project("./exemple_1")
state_0 = p.factory.blank_state(addr= 0x401122)

sm = p.factory.simulation_manager(state_0)
p.hook(0x40113f, hook_atoi,5)

print("[+] Exploration en Cours ....")
sm.explore( find = 0x401150, avoid = 0x401157)
print("[+] Arrivé à destination")

if len(sm.found) == 0:
	print("[-] Il n'a pas été possible d'atteindre la destination")
	quit()
else :
	print("[+] Détermination de l'input valide")

	# Récupération de l'état qui est arrivé dans le bon bloc
	found = sm.found[0]
	# Appel au solveur pour retourner au moins une solution
	res = found.solver.eval(arg_symb)
	print("[+] Le bon input est : ",hex(res))
```

En exécutant ce script, on obtient bien le bon *input* !
```
[+] Exploration en Cours ....
[i] La fonction atoi a été hookée  
[+] Arrivé à destination  
[+] Détermination de l'input valide  
[+] Le bon input est :  0xdeadbeef
```
Maintenant, passons à l'explication des différentes étapes :
1. Tout d'abord, on vérifie qu'il y a au moins un état qui est arrivé à destination (bloc vert), sinon, on quitte
2. Si tout est ok, on récupère le premier état de type `found` (ici il n'y en a qu'un mais parfois il peut y en avoir plusieurs)
3. On appelle le solveur de notre état `found` via `found.solver.eval`. Les deux paramètres possibles sont :
	1. La variable symbolique dont on veut au moins une valeur possible
	2. Le format du résultat final (facultatif), par exemple : `cast_to=bytes` afin d'avoir des bytes en sortie. En ce qui nous concerne, un entier fera l'affaire.
5. Affichage du bon input

#### Comment le solveur arrive-t-il à trouver le bon input ?

Etant donné que nous avons vu comment, globalement, fonctionne un solveur, il va être plus simple de comprendre comment angr réussit à trouver le bon input.

Tout d'abord, rappelez vous, nous avons déclaré la variable symbolique représentant l'input de cette manière : `arg_symb = claripy.BVS('argv[1]', 8*8)`. A ce stade `arg_symb` ne dispose d'aucune contrainte et peut donc valoir n'importe quelle valeur de 64 bits.

Toutefois, lors de l'exécution du programme, cette variable symbolique va être soumise à une ou plusieurs contraintes qui seront automatiquement ajoutées par angr.

Par exemple, lors du retour de `atoi`, le registre `rax` contient notre variable symbolique `arg_symb`. Or une **comparaison** est immédiatement réalisée ensuite :

![](/assets/images/introduction_a_l_execution_symbolique_avec_angr/after_atoi_comp.png)

Ainsi, pour que l'instruction `jnz` ne soit pas exécutée et que l'on aille directement dans le bloc "vert", il est nécessaire que la condition suivante soit vérifiée : `eax == 0xdeadbeef`. Or `eax` contient les 32 bits de **poids faible** de `arg_symb`. 

De cette manière, angr ajoute automatiquement une contrainte du type `arg_symb[32:64] == 0xdeadbeef`.

> Comme la comparaison est effectuée sur 32 bits via `eax`, il n'y a aucune contrainte sur les 32 bits de **poids fort** de `rax`.
{: .prompt-tip }

## S'exercer

Voici un petit programme assez simple qui prend un chaîne de caractère hexadécimale et vérifie s'il s'agit de la bonne clé.

Quelques différences avec le programme que nous avons étudié sont à noter :
- L'input n'est plus récupérée via `argv`
- Plusieurs fonctions de la libc ont été ajoutées ( les hooker ?)

L'objectif n'est pas de devenir un pro de angr avec ce challenge mais de savoir utiliser les **fonctionnalités de base** de angr.

```c++
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

unsigned long long hash(unsigned long long arg)
{
  unsigned long long result = 0;
  unsigned char x =0;
  unsigned long long temp =0;
  
  unsigned long long key =0xef9e8bd8f3afe9eb;
  for (int i =0;i<8;i++)
  {
    x = (arg >> (i*8)) &0xff;
    switch(x % 2) 
    {
            case 0:
                temp = 0xff;
                break;
            case 1:
                temp = x ^ (unsigned char)((key >> (i*8)) &0xff);
                break;

      }

      result = result | (temp << (i*8));
  }
    return result;
}
int main() 
{
    char key_buffer[16] = {0};
    puts("Give me the key in hexadecimal : ");
    read(0,key_buffer,16);
    unsigned long long arg = strtoull(key_buffer,NULL,16);
    if (hash(arg) == 0xdeadbeefcafebabe) 
    {
      puts("Win !");
      return 1337;
    } 
    else 
    {
      puts("Loose !");
      return -1;
    }
}

```

Pour le compiler : `gcc -no-pie main.c -o exe`.

## Résumé

Nous avons pu voir ensemble au cours de ce chapitre plusieurs points :

- Rappel sur ce qu'est l'**analyse statique** et l'**analyse symbolique**
- Les **états** sont des contextes d'exécution symbolique qui permettent de pouvoir parcourir plusieurs chemin lors d'une même exécution (symbolique). Les états diffèrent principalement par les **contraintes** appliquées à leurs variables
- Les **contraintes** permettent de restreindre la valeur que peut avoir une variable symbolique
- Le **SMT** solveur permet de prouver qu'une équation dispose d'une solution, plusieurs ou aucune. Ces équations sont réalisées à partir des contraintes sur les variables