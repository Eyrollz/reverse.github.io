---
title: Partie 25 - Annexes
date: 2023-10-06 10:00:00
categories: [Reverse, Introduction au reverse]
tags: [x86, reverse, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# Annexes

Dans cette page, vous trouverez plusieurs informations regroupées ensemble dont on a pu parler lors de ce cours :

- des astuces **Ida**
- des astuces **gdb**
- les **principales instructions x86**

> Si vous cherchez une info ou commande bien précise, n'hésitez pas à utiliser `Ctrl+F` 😉.
{: .prompt-tip }

## Astuces IDA

> **Astuce IDA** : Vous pouvez utiliser le raccourcis `N` pour **renommer** une **fonction**, un **label** ou une **variable** en ayant préalablement cliqué dessus avant de la renommer.
{: .prompt-tip }

> **Astuce IDA** : Pour modifier le **type** d'une **fonction** ou d'une **variable**, il suffit de cliquer dessus et d'appuyer sur `Y`.
{: .prompt-tip }

> **Astuce IDA** : Le raccourcis permettant d'assigner à des constantes des énumérations est `M`.
{: .prompt-tip }

> **Astuce IDA** : Il est possible de mettre un commentaire sur la même ligne que l'instruction sélectionnée dans la fenêtre de décompilation avec le raccourcis `/`.
> 
> Dans la fenêtre du code désassemblé, cela est possible avec `:` ou `;`.
{: .prompt-tip }

> **Astuce IDA** : Vous pouvez utiliser le raccourcis `Inser` pour saisir un commentaire avant l'instruction sélectionnée.
{: .prompt-tip }

> **Astuce IDA** : En utilisant la touche `Entrée`, vous pouvez ajouter des sauts de lignes, pratique lorsque l'on souhaite espacer le code.
{: .prompt-tip }

> **Astuce IDA** : Les variables nommées `v1`, `v2` etc. correspondent à des **variables locales** d'une fonction tandis que les variables `a1`, `a2` etc. correspondent aux **arguments** de la fonction.
{: .prompt-tip }

> **Astuce IDA** : Vous pouvez utiliser le raccourcis `G` pour aller à une adresse en particulier.
{: .prompt-tip }

> **Astuce IDA** : Vous pouvez utiliser le raccourcis `espace` pour basculer du mode "graphe" vers le mode "texte" et inversement.
{: .prompt-tip }

> **Astuce IDA** : En mode "graphe", vous pouvez modifier la couleur des blocs de base en cliquant sur l'icône la plus à gauche en haut du bloc.
{: .prompt-tip }

> **Astuce IDA** : Parfois, au lieu d'afficher une chaîne de caractères, IDA affiche un offset en mémoire plutôt que la `string` directement. Pour y remédier, aller dans `Edit`➡️ `Plugins` ➡️ `Hex-Rays Decompiler` ➡️ `Options` ➡️ `Analysis options 1` et décocher `Print only constant string literals`.
{: .prompt-tip }

> **Astuce IDA** : Il est souvent intéressant d'avoir les deux onglets désassembleur / décompilateur sur la même vue. Vous pouvez faire cela en déplaçant l'un des deux onglets. Vous pouvez ensuite synchroniser les deux vues en faisant un clic droit dans la fenêtre de décompilation et en cliquant sur `Synchronize with > IDA View`.
> 
> De cette manière, lorsque vous cliquerez sur un ligne ou que vous changerez de fonction, IDA affichera la ligne adéquate dans la fenêtre de désassemblage. 
{: .prompt-tip }

> **Astuce IDA** : Pour désactiver (ou réactiver) le *cast* des variables, c'est le raccourcis `Alt Gr + \`. Cela permet d'avoir du code plus lisible.
> 
> Mais attention, parfois les *casts* donnent des informations importantes, notamment lorsque l'on souhaite reprogrammer un algorithme en C, Python ou autre, il est nécessaire de faire attention à la taille des variables.
{: .prompt-tip }

> **Astuce IDA** : Une fois que vous avez trouvé l'adresse de base de votre programme, il suffit, dans IDA, d'aller dans `Edit` ➡️ `Segments` ➡️ `Rebase program` puis saisir l'adresse de base trouvée dans gdb avec `libs` et cliquer sur `Ok`.
{: .prompt-tip }

## Astuces gdb

> Certaines de ces commandes sont propres à `pwndbg`.
{: .prompt-warning }

Liste des formats : 

- **o** : octal
- **x** : hexadécimal
- **u** : décimal non signé
- **t** : binaire
- **f** : nombre à virgule (ou flottant)
- **a** : adresse
- **c** : char
- **s** : chaîne de caractères

**Tailles** définies dans gdb :

| Abréviation | Signification | Taille (en octets) |
|-------------|---------------|--------------------|
| `b`           | *byte*          | 1                  |
| `h`           | *half word*     | 2                  |
| `w`           | *word*          | 4                  |
| `g`           | *giant word*    | 8                  |

> **Astuce gdb** : Si un programme accepte des arguments via `argv`, il est possible de les spécifier lors de la commande `run`.
> 
> Exemple : `run arg1 arg2`
{: .prompt-tip }

> **Astuce gdb** : La commande `hb *0xaddr` (*hardware breakpoint*) permet d'insérer un point d'arrêt matériel à l'adresse `0xaddr` .
{: .prompt-tip }

> **Astuce gdb** : Vous pouvez utiliser `i b` (pour `info breakpoints`) afin de lister les points d'arrêts du programme.
> 
> Cela est très utile pour s'y retrouver. Chaque point d'arrêt ayant un numéro unique, il sera affiché dans cette commande.
{: .prompt-tip }

> **Astuce gdb** : Pour supprimer un point d'arrêt vous pouvez utiliser  `d N` (pour `delete N`) afin de supprimer le *breakpoint* numéro `N`.
{: .prompt-tip }

> **Astuce gdb** : Vous pouvez lister les zones mémoire mappées avec la commande `libs`.
{: .prompt-tip }

> **Astuce gdb** : L'instruction `starti` permet de charger le programme en mémoire et de **s'arrêter à la première instruction** de ce dernier, **sans l'exécuter**.
{: .prompt-tip }

> **Astuce gdb** : Vous pouvez quitter gdb avec les commandes `quit` ou `exit`. De manière plus rapide, vous pouvez utiliser `Ctrl+D`.
{: .prompt-tip }

> **Astuce gdb** : Pour exécuter l'instruction courante et s'arrêter à la prochaine, il est possible d'utiliser `si` ou `ni` (pour `step instruction` et `next isntruction`).
> 
> La différence entre les deux est que lors de l'appel d'une fonction, `ni` exécute la fonction jusqu'au retour alors que `si` entre dans la fonction et s'arrête à la première instruction.
{: .prompt-tip }

> **Astuce gdb** : Le fait de saisir à chaque fois `si` pour avancer d'une instruction peut être fastidieux 😤. Vous pouvez ~~spammer~~ utiliser la touche `Entrée` dans le terminal gdb afin de ré-exécuter la dernière commande que vous avez lancée précédemment.
{: .prompt-tip }

> **Astuce gdb** : Vous pouvez utiliser la commande `c` (ou `continue`) pour poursuivre l'exécution du processus jusqu'à arriver à un point d'arrêt.
{: .prompt-tip }

> **Astuce gdb** : Vous pouvez utiliser le raccourcis `fin` (ou `finish`) pour finir l'exécution d'une fonction jusqu'à atteindre l'adresse de retour et s'y arrêter.
{: .prompt-tip }

> **Astuce gdb** : La commande `p` (ou `print`) permet d'afficher une valeur quelconque ou la valeur d'une registre.
> 
> Si la valeur à afficher est une adresse (ou pointeur), elle ne sera pas déréférencée.
{: .prompt-tip }

> **Astuce gdb** : Pour afficher un registre, il suffit de le préfixer avec le signe `$`. Exemple : `print $reg`.
{: .prompt-tip }

> **Astuce gdb** : Vous pouvez utiliser le raccourcis `x` ( pour `explore`) afin d'examiner le contenu d'une zone mémoire.
{: .prompt-tip }

> **Astuce gdb** : Vous pouvez spécifier un nombre d'éléments à afficher avant les formats afin d'afficher plus ou moins de données en mémoire. 
{: .prompt-tip }

> Le **nombre d'éléments** à afficher ainsi que **la taille** ne sont utilisables qu'avec `x`. Cela ne **fonctionnera pas** avec `print` où seuls les formats (décimal, binaire, hexadécimal ...) sont utilisables.
{: .prompt-warning }

> **Astuce gdb** : Avec `x`, vous pouvez également donner en argument une expression avec des opérations (addition, soustraction, multiplication ...).
> 
> Cela peut être pratique pour afficher une donnée dans un tableau dont on connait l'index et l'adresse de base. Par exemple, pour afficher la 5ème case d'un tableau d'éléments de 64 bits : `x 0x401000+8*5` (en supposant que le tableau soit stocké à partir de l'adresse `0x401000`).
{: .prompt-tip }

> **Astuce gdb** : La commande `search` de pwndbg permet de rechercher des motifs en mémoire.
{: .prompt-tip }

> **Astuce gdb** : La commande `set` permet d'écrire dans des registres, variables et la mémoire.
{: .prompt-tip }

> **Astuce gdb** : Vous pouvez utiliser `rel` (pour `reload`) afin de rafraîchir la GUI de pwndbg et voir les changements effectifs.
{: .prompt-tip }

> **Astuce gdb** : Pour modifier une zone mémoire pointée par un registre, il est possible d'utiliser `set *$reg = value`.
> 
> Pour modifier directement les données pointées par une adresse : `set *0xaddr = value`.
{: .prompt-tip }

> **Astuce gdb** : Si vous ne souhaitez modifier qu'un seul octet (au lieu de 4 par défaut) vous devez le spécifier. Exemple : `set {byte}0x401020 = 0xf5`.
{: .prompt-tip }

## Instructions x86

### `mov reg_d, value`

#### Opérandes 
- `reg_d` : registre de destination
- `value` : valeur immédiate (ou concrète, constante). 

#### Détails 
Cette forme est la plus simple : elle affecte la valeur `value` au registre de destination `reg_d`.

C'est une manière de réaliser des affectations de valeurs concrètes (immédiates).

#### Exemple
Imaginons que `eax` vaille `0xaabbccdd` puis que l'on exécute l'instruction `mov eax, 0xdeadbeef`. Alors la valeur de `eax` deviendra `0xdeadbeef`.

#### Équivalent en C

```cpp
// Initilisation du registre
int x = 0xaabbccdd; // eax

// Equivalent de : mov eax, 0xdeadbeef
x = 0xdeadbeef;
```

### `mov reg_d, reg_s`

#### Opérandes 
- `reg_d` : registre de destination
- `reg_s` : registre source 

#### Détails 
Le contenu du registre source `reg_s` est copié dans le registre de destination `reg_d`.

C'est une manière d'affecter le contenu d'une variable à une autre.
#### Exemple 

```nasm
mov eax, 0xaabbccdd
mov ebx, 0x11223344 

mov ebx, eax ; ebx == 0xaabbccdd
```

#### Équivalent en C

```cpp
// Initilisation des registres
int a = 0xaabbccdd; // eax
int b = 0x11223344; // ebx

// Equivalent de : mov ebx, eax
b = a; // b = 0xaabbccdd
```

### `mov reg_d, [reg_p]` 

#### Opérandes 
- `reg_d` : registre de destination
- `reg_p` : registre pointant vers une zone mémoire

#### Détails 
Cette forme est un peu plus complexe que les précédentes car elle fait appel à la notion de **pointeur**.

Ici `reg_d` est le registre de destination qui recevra une valeur, jusque-là rien de bien nouveau. Par contre, `reg_p` ne contient pas la valeur qui sera copiée mais **un pointeur vers la valeur** en question.

Ainsi, c'est la valeur pointée par `reg_p` qui est copiée dans `reg_d`.

C'est une manière de **lire des données** depuis la **mémoire**.

#### Exemple
Imaginons que je veuille exécuter ces instructions :

```nasm
mov eax, 0x700000F0 ; 0x700000F0 -> 0x1a2b3c4d
mov ebx, 0xcafebabe

mov ebx, [eax]
```

On suppose également que l'adresse `0x700000F0` pointe vers l'entier de 4 octets `0x1a2b3c4d`. Lorsque la dernière instruction `mov ebx, [eax]` sera exécutée, alors `ebx` vaudra `0x1a2b3c4d`. Vous voyez la logique ?

#### Légères variantes

Il existe quelques variantes où un offset (positif ou négatif) est ajouté au registre `reg_p`, par exemple :

```nasm
mov edx, [eax + 8]
mov ecx, [esi - 0x2000]
```

#### Équivalent en C
Cette forme est très similaire à l'utilisation de pointeurs en C :

```cpp
// Initilisation des registres
int *a = 0x700000f0; // eax
int b = 0xcafebabe; // ebx

// Initilisation de la mémoire 
*a = 0x1a2b3c4d;

// Equivalent de : mov ebx, [eax]
b = *a; // b = 0x1a2b3c4d
```

### `mov [reg_p], reg_s`

#### Opérandes 
- `reg_p` : registre pointant vers une zone mémoire
- `reg_s` : registre source

#### Détails 
Normalement, si vous avez bien saisi le principe de l'instruction `mov reg_d, [reg_p]` vous devriez deviner le fonctionnement de celle-ci.

En fait il s'agit de l'inverse de la précédente instruction. En effet, ici on copie la valeur du registre `reg_s` vers la zone mémoire pointée par `reg_p`.

C'est une manière d'**écrire des données** en **mémoire**.

#### Exemple
Reprenons le précédent exemple, nous avons cette fois-ci :

```nasm
mov eax, 0x700000F0 ; 0x700000F0 -> 0x1a2b3c4d
mov ebx, 0xcafebabe

mov [eax], ebx ; 0x700000F0 -> 0xcafebabe
```

#### Légères variantes

Il existe quelques variantes où un offset (positif ou négatif) est ajouté au registre `reg_p`. Il est également possible de remplacer `reg_s` par une valeur immédiate. Par exemple :

```nasm
mov [ebp + 8], edi
mov [esi - 0x200], 0xdeadbeef
```

#### Équivalent en C

```cpp
// Initilisation des registres
int *a = 0x700000f0; // eax
int b = 0xcafebabe; // ebx

// Initilisation de la mémoire 
*a = 0x1a2b3c4d; // 0x700000f0 -> 0x1a2b3c4d

// Equivalent de : mov [ebx], eax
*a = b; // 0x700000f0 -> 0xcafebabe
```

### Résumé des différentes formes de `mov`

Je sais, ça fait beaucoup d'informations d'un coup, voici ainsi un résumé avec un exemple pour chacun des 4 formes possibles. Supposons que dans les 4 cas l'état initial est le suivant :

![](/assets/images/introduction_au_reverse/init_mov_asm_bis.png)

Alors le résultat est : 

![](/assets/images/introduction_au_reverse/mov_summary.png)

> Les valeurs en 🔴 sont celles qui ont changé lors de l'exécutions de l'instruction tandis que celles en ⚫ sont les valeurs à l'origine du changement.
{: .prompt-tip }

### `lea reg, [...]`

#### Opérandes 
- `reg` : registre de destination
- `[...]` : valeur qui est souvent une adresse mémoire

#### Détails 

Cette instruction a ainsi une seule forme où la première opérande est toujours un registre, la seconde opérande est une valeur qui est souvent une adresse vers une zone mémoire. 

Ce que fait `lea` est tout simplement la copie de l'opérande de droite, **sans la déréférencer**, vers le registre de destination.

Voici quelques exemples :

```nasm
lea eax, [0x400000] ; ici eax = 0x400000 
lea edx, [ebp+8]    ; ici edx = ebp +8
lea ecx, [ebx+eax]  ; ici ecx = ebx+eax
```

#### Exemple

> Comme `lea` ne déréférence pas la seconde opérande, l'instruction `lea eax, [0x400000]` copie bien `0x400000` dans `eax` et non pas la valeur pointée par `0x400000`.
{: .prompt-warning }

En fait, plus simplement, `lea` copie la valeur entre les crochets vers le registre de destination. En d'autres termes, `lea reg, [...]` est équivalente à `mov reg, ...`.

J'en vois déjà certains froncer les sourcils 🤨.

> Mais si cela est équivalent à faire un `mov`, pourquoi se casser la tête avec une instruction en plus ?
{: .prompt-info }

En fait, contrairement à `mov`, l'instruction `lea` permet de faire de petites opérations au niveau de l'opérande de droite. Par exemple, si je souhaite affecter à `ecx` la somme de `ebx` et `eax` en utilisant `mov`, je suis obligé d'utiliser une instruction supplémentaire telle que `add` pour faire l’addition et ensuite stocker le résultat dans `ecx` avec `mov`.

Tandis qu'avec `lea`, je peux simplement faire : `lea ecx, [ebx + eax]`. Vous savez quoi ? On peut même faire `lea ecx, [ebx + eax*2]`😎.

Ainsi, `lea` permet de :

- **Stocker** le résultat de **simples opérations** en écrivant une seule instruction
- De **manipuler des adresses** en y ajoutant, ou non, un offset

> S'il n'y avait qu'une seule chose à retenir de `lea` : il s'agit d'un `mov` qui copie la "valeur entre crochets" vers la destination.
{: .prompt-tip }

### `add reg_d, reg_s`

#### Opérandes 
- `reg_d` : registre de destination
- `reg_s` : registre source

#### Détails 

"Add" en anglais signifie "**ajouter**".

Cette instruction réalise ainsi deux actions : 
- **addition** de la valeur du registre source avec celui de destination
- **stockage** du résultat (la somme) dans le registre de destination

C'est de cette manière que sont réalisées les **additions**.

> Lorsque la somme des deux termes dépasse le plus grand entier que peut stocker le registre de destination, le résultat est tronqué pour qu'il puisse y être stocké
{: .prompt-warning }

#### Exemple

Faisons la somme de `0xf0000034` et `0x20001200` :

```nasm
mov eax, 0xf0000034
mov ebx, 0x20001200

add eax, ebx ; eax = 0x10001234 et non pas 0x110001234 car le résultat est tronqué aux 32 bits de poids faible
```
#### Équivalent en C

```cpp
// Initilisation des registres
int a = 0xf0000034; 
int b = 0x20001200; 

a = a + b;
```

#### Autres formes

Il existe plusieurs autres formes :
- `add reg, value` 
- `add [ptr], value`
- `add reg, [ptr]`

Leur fonctionnement est toujours le même : somme des deux termes et stockage dans l'opérande de destination. 

> Toutes les instructions, sauf mention contraire (comme `lea`), déréférencent les pointeurs vers des zones mémoire.
> 
> Dans les précédentes formes, ce n'est donc pas le pointeur `ptr` qui est utilisé dans la somme mais la valeur pointée par `ptr` qui est `[ptr]` (qui serait `*ptr` en C). 
{: .prompt-warning }

### `and ope_d, ope_s`

#### Opérandes 
- `ope_d` : opérande de destination. Peut être :
	- un **registre**
	- un **pointeur**
- `ope_s` : opérande source. Peut être 
	- une **valeur immédiate** 
	- un **registre** 
	- un **pointeur** (vers une zone mémoire) 

#### Détails 

L'instruction `and` réalise un "**et logique**" entre les bits des deux opérandes. Le résultat est ensuite sauvegardé dans la première opérande (qui ne peut donc pas être une valeur immédiate).

#### Exemple

```nasm
mov eax, 0xff00ff00
mov ebx, 0xabcdef12

and eax, ebx ; eax = 0xab00ef00
```

#### Équivalent en C

```cpp
int a = 0xff00ff00; 
int b = 0xabcdef12; 

a = a & b;
```

#### Autres formes

Il existe d'autres [formes](https://c9x.me/x86/html/file_module_x86_id_12.html) en fonction du type d'opérandes mais le principe est toujours le même.

### `sub ope_d, ope_s`

#### Opérandes 
- `ope_d` : opérande de destination. Peut être :
	- un **registre**
	- un **pointeur**
- `ope_s` : opérande source. **Valeur soustraite**. Peut être 
	- une **valeur immédiate** 
	- un **registre** 
	- un **pointeur** 

#### Détails 

"Sub" provient de "substract" qui signifie **soustraire**.

Cette instruction réalise ainsi deux actions : 
- **soustraction** de l'opérande source avec l'opérande de destination `ope_d - ope_s`.
- **stockage du résultat** (la différence) dans l'opérande de destination

C'est de cette manière que sont réalisées les **soustractions**.

> Contrairement à `add`, l'**ordre** des opérandes est **important** dans `sub`. En effet, en inversant les opérandes, on inverse le **signe du résultat**.
{: .prompt-warning }

#### Exemple

Faisons la différence de `0xf0000034` avec `0x10000034` :

```nasm
mov eax, 0xf0000034
mov ebx, 0x10000034

sub eax, ebx ; eax = 0xe0000000
```

#### Équivalent en C

```cpp
int a = 0xf0000034; 
int b = 0x10000034; 

a = a - b;
```

#### Autres formes

Il existe d'autres [formes](https://c9x.me/x86/html/file_module_x86_id_308.html) mais le principe est toujours le même.

### `cmp ope_d, ope_s`

#### Opérandes 
- `ope_d` : opérande de destination. Peut être :
	- un **registre**
	- un **pointeur**
- `ope_s` : opérande source. Peut être :
	- une **valeur immédiate** 
	- un **registre** 
	- un **pointeur** 

#### Détails 

La comparaison avec `cmp` est effectuée d'une manière qui peut nous paraître bizarre. En effet, `cmp` effectue la soustraction suivante `sub ope_d, ope_s` mais sans stocker le résultat. Ainsi le contenu des **opérandes restent inchangées**.

Par contre, quelques *flags* parmi les **EFLAGS** vont être **changés** en fonction des valeurs des opérandes et du résultat. C'est à partir de ces EFLAGS que l'on saura si les opérandes sont **égales** ou s'il y en a une plus **grande/petite** que l'autre etc.

> Il est important que vous ayez en tête la manière dont les entiers sont représentés en informatique, notamment les entiers signés avec le [complément à deux](https://qkzk.xyz/docs/nsi/cours_premiere/donnees_simples/complement_a_deux/1_cours/).
{: .prompt-tip }

Plus précisément, ce sont les *flags* `ZF`, `SF`, `CF` et `OF` qui nous intéressent principalement (et dans une moindre mesure `PF`). Nous les avions déjà vus brièvement précédemment, profitons-en pour nous rafraîchir la mémoire et rentrer plus dans les détails. 

- `ZF` (Zero Flag) : 
	- **1** si les deux opérandes sont égales. La différence des deux termes vaut donc 0.
	- **0** si les deux opérandes sont différentes.
- `SF` (Sign Flag) :
	- **1** si le bit de poids fort du résultat est non nul. Dans le cas d'une opération signée cela implique qu'il est négatif. Dans le cas où elle est non signé, ce *flag* n'a pas d'importance.
	- **0** si le bit de poids fort du résultat est nul
	- **Exemple** : Prenons la soustraction signée suivante :`0x5 - 0x20 = -0x1b`. Le résultat étant négatif, le complément à deux de `0x1b` est `0xe5` qui s'écrit sur 8 bits en binaire `0b11100101`. Le bit de poids fort étant à `1`, `SF` l'est également. Etant donné qu'il s'agit d'une opération signée `SF` nous permet de savoir que le résultat est négatif.
- `CF` (Carry Flag) :
	- **1** si le résultat possède une retenue. 
	- **0** si le résultat ne possède pas de retenue
	- **Exemple** : Par exemple, pour l'instruction `add al, bl` sur 8 bits où `al` vaut `0xFF` et `bl` vaut `0x01`, le résultat est `0xFF + 0x01 = 0x100` qui ne tient pas sur les 8 bit de `al`. Cela génère donc une retenue. Lors d'une soustraction `a - b`, **une retenue est générée** lorsque `b` est plus grand que `a`.
- `OF` ([Overflow Flag](https://fr.wikipedia.org/wiki/Indicateur_de_d%C3%A9bordement)) :
	- **1** si un débordement a lieu avec des valeurs signées. Par exemple, cela peut avoir lieu lorsqu'il y a un résultat négatif d'opérandes positifs et inversement. Ce bit n'a pas d'importance lorsque l'on manipule des valeurs non signées.
	- **0** s'il n'y a pas eu de débordement
	- **Exemple** : Prenons l'addition signée suivante :`0x7F + 0x8 = 0x87`. Ici, le bit de poids fort de `0x87` est à `1` : il s'agit donc d'un résultat négatif (`-121`). Pourtant, les deux termes sont strictement positifs. Il y a donc eu un débordement (`overflow`).
- `PF` (Parity Flag) :
	- `1` si le nombre de bits su résultat est pair
	- `0` sinon

> N'hésitez pas à utiliser [asmdebugger](http://asmdebugger.com/) pour faire **quelques tests**. Les 4 `flags` étudiés sont affichés sur le site lors de l'exécution des instructions.
> 
> En effet, si l'utilisation de ces *flags* vous paraît difficile, sachez que c'est normal car cela fait intervenir des notions que l'on utilise pas, en tant qu'humain, tous les jours comme le complément à deux pour représenter des nombres négatifs. 
{: .prompt-tip }

Lors d'une comparaison avec `cmp`, le processeur ne sait pas si les opérandes sont signées ou non. En fait, il s'en moque à ce stade. C'est pourquoi il va modifier, si besoin est, ces 4 *flags* bien que certains soient plutôt utilisés lors d'opérations signées (`SF` et `OF`) ou non signées (`CF`).

#### Exemples

Voici quelques exemples :

| Instruction  | ZF | SF | CF | OF |
|--------------|----|----|----|----|
| `cmp 1, 5`     |    |  ✅  | ✅   |    |
| `cmp 5, 1`     |    |    |    |    |
| `cmp 5, 5`     |  ✅  |    |    |    |
| `cmp 4, 255`   |    |    |  ✅  |    |
| `cmp 127, 129` |    |  ✅  |  ✅  |  ✅  |

Je vous conseille de représenter les entiers sous forme binaire et de faire attention à la représentation du complément à deux. En effet, `129` s'il n'est pas signé vaut `129` mais s'il est signé, il vaut `-127`.

#### Équivalent en C

Pour l’instruction `cmp`, il n'y a pas réellement d'équivalent en C. En fait, `cmp` n'est jamais (sauf exceptions) utilisées autrement qu'avec des sauts. Ainsi, représenter `cmp` tout seul dans du code C n'a pas de sens. Par contre, dans toutes les conditions du type `if`, `else` vous y trouverez un `cmp` (ou `test`) dans le code assembleur associé.

### `test ope_d, ope_s`

#### Opérandes 
- `ope_d` : opérande de destination. Peut être :
	- un **registre**
	- un **pointeur**
- `ope_s` : opérande source. Peut être :
	- une **valeur immédiate** 
	- un **registre** 

#### Détails 

Cette instruction est également utilisée pour réaliser des comparaisons mais son fonctionnement sous-jacent est différent de `cmp`. 

`test` va exécuter l'instruction `and ope_d, ope_s` sans stocker le résultat mais en mettant à jour des *flags* suivants : `SF`, `ZF` et `PF`. `test` est souvent utilisé pour savoir si un registre est nul ou non.

#### Exemple

L'instruction `test eax, eax` permet de voir si `eax` est **nul ou non**. En effet, lors de l'exécution de cette instruction, si `ZF == 1`, c'est que `eax` est nul. Sinon, cela signifie qu'il est non nul.

#### Équivalent en C

Même remarque que pour `cmp` : il n'y a pas réellement d'équivalent direct en C.

### `jmp dest`

#### Opérandes 
- `dest` : destination du saut. Peut être :
	- une **valeur immédiate** (exemple : adresse **relative** ou **absolue**)
	- un **registre**
	- un **pointeur**

#### Détails 

Unique instruction permettant de réaliser des **sauts inconditionnels** afin de "sauter" vers l'adresse de destination. Cela permet de pouvoir exécuter des instructions qui ne sont pas toujours situées linéairement dans le code.

> La différence entre un saut et un appel de fonction `call` est que l'on ne se préoccupe pas de sauvegarder **l'adresse de retour** afin de pouvoir y retourner plus tard.
{: .prompt-tip }

Lorsque l'opérande `dest` est une valeur immédiate, il peut s'agir d'une adresse **absolue** ou **relative** :

- adresse **absolue** : l'adresse est "**codée en dur**" dans l'opcode de l'instruction. Cela permet de sauter **plus loin** dans le code mais l'instruction prend plus de place.
	- Exemple : `e9 d8 12 00 00          jmp    0x12dd`
- adresse **relative** : seule la **différence** entre l'adresse courante de `eip` et l'adresse de destination est insérée dans l'opcode. Cela permet d'avoir des opcodes plus courts mais de sauter **moins loin**.
	- Exemple : `eb 2a                   jmp     short 0x12DC`

> Concernant les adresses absolues, elles ne sont pas insérées **tel quel** dans l'opcode. En effet, il est nécessaire de prendre en compte **la taille de l’instruction** de saut (par exemple 5 octets) avant d'insérer l'adresse de destination. C'est pourquoi l'opcode de l'exemple contient `e9 d8 12` et non pas `e9 dd 12`.
{: .prompt-tip }

Bien que le mnémonique `jmp` utilisé soit le même, il existe différentes forme où `dest` n'est pas toujours une adresse. Cela peut, en effet, être un **pointeur** ou **registre**. 

Le souci, en tant que *reverser*, est qu'il ne sera **pas toujours possible de savoir** directement vers quelle adresse le processeur va sauter lorsqu'un registre (ou pointeur) va être utilisé. En analyse statique, il sera nécessaire de déterminer les différentes valeurs que peut prendre le registre afin de trouver les **potentielles destinations**.

Le fait d'utiliser un registre comme opérande est très commun dans la modélisation des `switch` en assembleur après compilation.

#### Exemple

```nasm
jmp 0x401020
jmp rax
jmp [ebx]

```

#### Équivalent en C

Les sauts inconditionnels `jmp` sont l'équivalent de `goto` en C :

```cpp
#include <stdio.h>

int main() {
    int i = 0;

    start_loop:

    if (i < 5) {
        printf("i = %d\n", i);
        i++;
        goto start_loop;  // Sauter à l'étiquette start_loop
    }

    return 0;
}
```

### `jcc dest`

#### Opérandes 
- `dest` : destination du saut. Peut être :
	- une **valeur immédiate** (exemple : adresse **relative** ou **absolue**)

#### Détails 

`jcc` n'est **pas un mnémonique** en soi. Il s'agit d'un terme générique pour désigner le mnémonique de tous les **sauts conditionnels**. Les points communs de tous ces sauts sont les suivants :

- Ils utilisent certains *flags* parmi les EFLAGS afin de savoir s'il faut sauter
- Lorsque que le saut n'est pas exécutée, c'est l’instruction **située immédiatement après** le saut qui est réalisée
- Ils sont **précédés** d'une instruction `cmp` ou `test`

Si vous retenez ça, vous avez retenu 60% du fonctionnement des sauts conditionnels. Le reste consiste seulement à se rappeler de ce que signifie chaque mnémonique et quels *flags* sont utilisés.

Voici les principaux sauts que vous pourrez rencontrer :

> Selon le désassembleur utilisé, il peut y avoir quelques **différences** dans le mnémonique comme `jz` (*jump if zero*) qui peut être désigné `je` (*jump if equal*) mais qui représentent exactement la même instruction.
{: .prompt-tip }

| Mnémonique(s)      | Description                                    | Signe des opérations | Cas d'utilisation                   | Condition de saut     |
|-----------------|------------------------------------------------|----------------------|-------------------------------------|-----------------------|
| `jo`              | **J**ump if **o**verflow                               |                      | Détection de débordement            | `OF == 1`               |
| `jno`             | **J**ump if **n**ot **o**verflow                           |                      | Détection de débordement            | `OF == 0`               |
| `js`              | **J**ump if **s**ign                                   |                      | Tester le signe                     | `SF == 1`               |
| `jns`             | **J**ump if **n**ot **s**ign                               |                      | Tester le signe                     | `SF == 0`               |
| `jz` / `je`         | **J**ump if **z**ero / **e**qual                           |                      | Tester l'(in)égalité                | `ZF == 1`               |
| `jnz` / `jne`       | **J**ump if **n**ot **z**ero / **n**ot **e**qual                   |                      | Tester l'(in)égalité                | `ZF == 0`               |
| `jb` / `jnae` / `jc`  | **J**ump if **b**elow / **n**ot **a**bove or **e**qual / **c**arry     | Non signé            | Tester la supériorité / infériorité | `CF == 1`               |
| `jnb` / `jae` / `jnc` | **J**ump if **n**ot **b**elow / **a**bove or **e**qual / **n**ot **c**arry | Non signé            | Tester la supériorité / infériorité | `CF == 0`               |
| `jbe` / `jna`       | **J**ump if **b**elow or **e**qual / not **a**bove             | Non signé            | Tester la supériorité / infériorité | `CF == 1 \|\| ZF == 1`  |
| `jnbe` / `ja`       | **J**ump if **n**ot **b**elow or **e**qual / **a**bove             | Non signé            | Tester la supériorité / infériorité | `CF == 0 && ZF == 0`    |
| `jl` / `jnge`       | **J**ump if **l**ess / **n**ot **g**reater or **e**qual            | Signé                | Tester la supériorité / infériorité | `SF != OF`              |
| `jnl` / `jge`       | **J**ump if **n**ot **l**ess / **g**reater or **e**qual            | Signé                | Tester la supériorité / infériorité | `SF == OF`              |
| `jng` / `jle`       | **J**ump if **n**ot **g**reater / **l**ess or **e**qual            | Signé                | Tester la supériorité / infériorité | `ZF == 1 \|\| SF != OF` |
| `jg` / `jnle`       | **J**ump if **g**reater / **n**ot **l**ess or **e**qual            | Signé                | Tester la supériorité / infériorité | `ZF == 0 && SF == OF`   |

Il est à noter qu'il n'existe pas une seule manière de représenter une condition du C vers l'assembleur. Prenons par exemple le code suivant :

```cpp
unsigned int x = ...;
unsigned int y = ...;
if (x > y )
{
	// Code A
}
else
{
	// Code B
}
```

On peut très bien faire :
```nasm
cmp x, y
ja addr_code_A
code_B
```

ou :

```nasm
cmp x, y
jbe addr_code_B
code_A
```

Il faut donc être attentif lorsque l'on analyse du code assembleur pour savoir ce qui va être exécuté et sous quelles conditions.

#### Exemples
```nasm
jz 0x555555550102
jns 0x405987
```

#### Équivalent en C

Selon le **signe des variables** comparées et le **type de comparaison** utilisé, certains sauts vont être utilisés plutôt que d'autres (les différents mnémoniques d'une même instruction ont été omis par souci de concision) :

```cpp
int x = ...;
int y = ...;

if (x < 0) // js ou jns
{
	//...
}

if (x == y) //jz ou jnz
{
	//...
}

if(x < y) // jl ou jnl 
{
	//...
}

if(x >= y) // jnl ou jl
{
	//...
}

if(x <= y) // jle ou jnle
{
	//...
}

```

#### Autres formes

Il existe d'autres [sauts](http://unixwiz.net/techtips/x86-jumps.html) mais que l'on rencontre moins souvent.

### `cdq`

#### Opérandes 
- Cette instruction n'a pas d'opérandes

#### Détails 

`cdq` est l'abréviation de `convert dword to qword`. Vous l'avez compris, cela devrait donc permettre de convertir un `dword` (4 octets) en un `qword` (8 octets), mais comment ? 

Tout d'abord, cette instruction ne s'applique que sur le registre `eax` (ou ses dérivées). C'est pourquoi elle ne dispose pas d'opérandes. De plus, cette instruction garde le signe de l'ancienne valeur lors de la conversion vers la nouvelle valeur.

En x86_64 on a des registres de 64 octets, ce qui n'est pas le cas en x86. Ainsi, pour doubler la taille des données contenues dans `eax`, c'est le registre `edx` (ou ses dérivées) qui va être utilisé de cette manière :

- si le nombre dans `eax` est **négatif** (bit de poids fort égal à `1`), alors `edx` est rempli de `1`
- si le nombre dans `eax` est **positif** (bit de poids fort égal à `0`), alors `edx` est rempli de `0`

> Cette manière de générer une nouvelle valeur à partir d'une valeur signée est ce que l'on appelle l'**extension de signe**.
{: .prompt-tip }

Ainsi on obtient une valeur de taille double en concaténant les deux registres sous la forme : `edx:eax`.

Cette instruction est très utilisée lors des divisions signées afin d'avoir un résultat cohérent et correct.
#### Exemples
```nasm
mov eax, 0x70001234
cdq ; edx:eax = 0x00000000:0x70001234

mov eax, 0x80001234
cdq ; edx:eax = 0xffffffff:0x80001234
```

#### Équivalent en C

Il n'y pas a pas d'équivalent directe en C.

#### Autres formes

Il existe plusieurs dérivées mais dont le principe d’extension de signe est le même :

- `cwd` (`convert word to dword`): la valeur convertie est contenue dans `dx:ax`
- `cqo` (`convert qword to double qword`): la valeur convertie est contenue dans `rdx:rax` (disponible seulement en x86_64)

### `shr ope_d, n` et `sar ope_d, n`

#### Opérandes 
- `ope_d` : opérande de destination. Peut être :
	- un **registre**
	- un **pointeur**
- `n` : opérande source. Peut être :
	- une **valeur immédiate** 
	- un **registre** (seulement le registre `cl`)

#### Détails 

L'instruction `shr` (ou `shift right`) permet de réaliser un décalage des bits de `ope_d` de `n` bits vers la droite. 

> Avec l'instruction `shr` et toutes les autres instruction de `shift` (décalage), il n'y a pas de rotation des bits sortants.
> 
> Il existe d'autres instructions comme `ror`/`rol` qui réalise un décalage rotatif des bits. C'est-à-dire que des bits qui sortent, par exemple, par la gauche, "rerentrent" par la droite. 
{: .prompt-warning }

Ainsi, le décalage de `0b01110011` d'un bit vers la droite est `0b00111001`.

> En fait, lorsqu'il y a un bit sortant, il n'est pas réellement perdu dans la nature : il est sauvegardé dans le *flag* `CF` des EFLAGS. 
{: .prompt-tip }

Il existe l'instruction `sar` (ou `shift aritmetic right`) est basée sur le même principe de décalage que `shr`. La seule différence est que `sar` **prend en compte le signe** du nombre qui sera décalé.

Ainsi, si le bit de poids fort de `ope_d` est `1`, il sera réinitialisé à `1` après décalage. En fait `sar` agit en deux temps :

1. exécuter `shr` 
2. si le précédent nombre était **signé**, mettre le **bit de poids fort** du résultat à `1`

Voir les exemples ci-dessous pour comprendre de quoi il s'agit.

Ces instructions sont très utilisées pour réaliser des divisions par 2 d'un nombre (et dont le reste est dans le *flag* `CF`). En effet, le décalage d'un bit vers la droite revient à diviser par `2`. Le décalage de `n` bits vers la droite revient à diviser par `2 puissance n`.

> Je ne vois pas en quoi décaler d'un bit vers la droite revient à diviser par deux ?
{: .prompt-info }

Pourtant c'est bien ce qui se passe lorsque l'on note un nombre en décimal et que l'on le décale d'une unité vers la droite, cela revient à diviser par 10. 

Prenons par exemple `213950`, en le décalant d'une unité vers la droite on obtient `21395`, ce qui revient bien à diviser par 10.

Avec la notation en binaire, c'est la même chose : **décaler d'un bit revient à diviser par deux**.

Ainsi, `sar` et `shr` sont très utilisés pour réaliser des divisions de puissances de 2.

#### Exemple

```nasm
    mov eax, 0x80000001   (0b10.....001)
    shr eax, 1 ; eax = 0x40000000 (0b01.....000)
               ; CF == 1
               
    mov eax, 0x80000001   
    sar eax, 1 ; eax = 0xc0000000 (0b11.....000)
               ; CF == 1
```

#### Équivalent en C

```cpp
int x = 0x80000001;
x = x >> 1; // x = 0xc0000000

int y = 0xdeadbeef;
y = y >> 13; // y = 0xfffef56d
```

#### Autres formes

De la même manière que `shr`/`sar` permettent de réaliser des décalages vers la droite, `shl`/`sal` permettent de réaliser des décalages vers la gauche avec le même principe.

A l'instar de la **division par puissances de 2** de `shr`/`sar`, `shl`/`sal` permettent de réaliser des **multiplications par puissances de 2** :

- ➡️ `shr`/`sar` : **division par puissances de 2**
- ⬅️`shl`/`sal` : **multiplication par puissances de 2**

Vous pouvez également jeter un œil aux [instructions](https://c9x.me/x86/html/file_module_x86_id_273.html) `rcl`/`rcr`/`rol`/`ror`. Leur fonctionnement de décalage est le même. La **principale différence** est qu'il y a une **rotation des bits** sortants.