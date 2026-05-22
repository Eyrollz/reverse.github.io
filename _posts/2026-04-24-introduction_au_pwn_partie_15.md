---
title: Partie 15 - Comprendre les vulnérabilités de type format string – introduction (1/5)
date: 2026-04-24 10:00:00
categories: [Pwn, Introduction au pwn]
tags: [x86, pwn, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# Comprendre les vulnérabilités de type *format string* – introduction (1/5)

Les *format strings* (ou chaînes de format 🇫🇷) ne sont pas des vulnérabilités en tant que telles. C'est ce que le programme en fait qui peut être une opportunité de l'exploiter.

![](/assets/images/introduction_au_pwn/fmt_strings_timeline.png)

Il s'agit d'un type de vulnérabilité assez ancien qui est beaucoup moins présent de nos jours en raison des protections ajoutées. Cela n'en fait pas moins un **classique** en termes de *pwn* et qui sait, peut-être que vous vous retrouverez un jour nez à nez avec un programme codé par des développeurs peu attentifs 😏. Par exemple, ces dernières années, les vulnérabilités [CVE-2024-45324](https://nvd.nist.gov/vuln/detail/CVE-2024-45324?utm_source=chatgpt.com) et [CVE-2025-52429](https://nvd.nist.gov/vuln/detail/CVE-2025-52429?utm_source=chatgpt.com) sont basées sur **l'exploitation de chaînes de format**.

De plus, même si ce type de vulnérabilité devient de plus en plus rare, il reste pertinent de le connaître, notamment dans les cas où vous contrôlez `eip` ainsi que le premier argument sur la pile. En redirigeant l’exécution vers `printf` (par exemple via la **GOT**), vous pouvez alors exploiter une vulnérabilité de type *format string* en contrôlant directement la chaîne de format.

> Ah on ne parle pas de la *heap* avant les *format strings* ?
{: .prompt-info }

Pour ne pas qu'il y ait d'incohérence dans l'enchaînement des chapitres, tous **les chapitres liés au tas sont regroupés** ensemble, dans un autre cours. Patience 😉.

> A partir de ce chapitre jusqu'à la fin de ce cours, nous allons partir du principe que **l'ASLR est toujours activée sauf mention contraire**.
> 
> N'oubliez pas de **l'activer** si ce n'est pas déjà le cas 😉 : `echo 2 > /proc/sys/kernel/randomize_va_space`.
{: .prompt-danger }

## Les chaînes de format, c'est quoi déjà?

Si vous êtes un minimum à l'aise avec le langage C, vous devriez déjà avoir utilisé moult fois des **chaînes de format**. Nous n'allons donc pas revoir en détails les bases du fonctionnement d'une chaîne formatée. Mais revoyons tout de même quelques rudiments.

Une **chaîne formatée** en C est une chaîne de caractères utilisée dans des fonctions comme `printf` ou `scanf`, qui contient du texte **et des instructions spéciales** appelées **spécificateurs de format** (comme `%d`, `%s`, `%f`, etc.) pour afficher ou lire des données de différents types. Vous savez, ces caractères bizarres qui nous ont traumatisés lorsque l'on a appris le langage C 😨. Et bien aujourd'hui, nous allons nous réconcilier et faire ami-ami avec eux !

Voici quelques exemples de chaînes de format : 

```cpp
int age = 0x213;
char nom[] = "LesZommes";

printf("Bonjour %s, vous avez %d ans.\n", nom, age);
```

Grâce aux spécificateurs de format, `printf` sait sous quelle forme traiter les données. Par exemple, l'âge qui est un entier valant `0x00000213` en mémoire va être converti en ASCII afin de pouvoir être affiché.

Ainsi, **selon le spécificateur de format** utilisé, les arguments passés en paramètre seront **interprétés différemment**. Bon, ça j'imagine que vous le savez déjà 🤓.

Par ailleurs, les fonctions du type `printf`, `snprintf` etc. sont nommées "[fonctions variadiques](https://fr.wikipedia.org/wiki/Fonction_variadique)", c'est-à-dire qu'elles acceptent un **nombre variable de paramètres**.

### Rappels

Afin que vous ne perdiez pas de temps à vous rappeler **à quoi sert chaque spécificateur de format**, vous trouverez dans le tableau ci-dessous les plus connus et les plus utilisés. Evidemment, nous allons en découvrir d'autres qui nous seront bien utiles en termes d'exploitation.

| Spécificateur | Par quoi sera remplacé le spécificateur dans la chaîne de caractères formée ?                      | Exemple                            | Résultat      |
| ------------- | -------------------------------------------------------------------------------------------------- | ---------------------------------- | ------------- |
| `%s`          | Le **contenu de la chaîne de caractères** du paramètre.                                            | Pointeur vers la chaîne `"azerty"` | `azerty`      |
| `%x` / `%X`   | La valeur **hexadécimale** du paramètre.                                                           | `0xaabbccdd`                       | `aabbccdd`    |
| `%d` / `%i`   | La valeur **décimale entière signée** du paramètre.                                                | `0xaabbccdd`                       | `-1430532899` |
| `%u`          | La valeur **décimale entière non signée** du paramètre                                             | `0xaabbccdd`                       | `2864434397`  |
| `%p`          | La **valeur hexadécimale** du paramètre **préfixée** par `0x` (ou `(nil)` si le paramètre est nul) | `0xaabbccdd`                       | `0xaabbccdd`  |
| `%c`          | Le paramètre sous forme de **caractère**.                                                          | `0x41`                             | `A`           |

## Vulnérabilité classique dans les chaînes de format

La vulnérabilité apparaît lorsque **l’utilisateur contrôle la chaîne de format** appelée par une fonction qui prend comme argument une chaîne de format.

Je sais que dit comme ça c'est du charabia donc voici **quelques exemples** pour comprendre de quoi il s'agit :

- `printf(entree_utilisateur)` au lieu de `printf("%s", entree_utilisateur)` ;
- `sprintf(dest,entree_utilisateur)` au lieu de `sprintf(dest, "%s", entree_utilisateur)`.

Avant de passer à l’exploitation de ce type de vulnérabilité, commençons par quelques cas simples pour s'échauffer et voir ce que l'on peut faire d'intéressant en manipulant un appel à `printf(entree_utilisateur)`.

### Afficher des valeurs avec `%p`

Il est temps de mettre la main à la pâte et voir comment fonctionne en interne une *format string*. Prenons l'exemple bateau suivant :

```cpp
#include "stdio.h"

int main(int argc, char **argv)
{

    if (argc != 2)
    {
        printf("[-] Pas assez ou trop d'arguments.\n");
        return -1;
    }

    printf("Bonjour ");
    printf(argv[1]);
    printf(" !\n");

    return 0;
}
```

> Le programme a été compilé en **32 bits** afin de comprendre plus facilement le fonctionnement de `printf`.
{: .prompt-tip }

Accès au conteneur Docker :

- ⬇️ **Téléchargement** : [pwn-fmt-exemple-1.zip](https://drive.proton.me/urls/FHGG25F9BC#U2YvwedwTruo)
- 🔎 **SHA256 & Analyse Virus Total** : [7d3010a42444da57800e622fb6e0c8df532b4640fc054dd30182170101fb8f27](https://www.virustotal.com/gui/file/7d3010a42444da57800e622fb6e0c8df532b4640fc054dd30182170101fb8f27)
- ⚙️ **Construction et lancement du conteneur** :

```sh
docker build -t pwn-fmt-exemple-1 .

docker run -it --rm -p 1234:1234 --cap-add=SYS_PTRACE --security-opt seccomp=unconfined pwn-fmt-exemple-1
```

Je pense que nous pouvons nous passer d'explications détaillées : le programme parle de lui-même 🙃. Le programme fait bien ce qu'il semble devoir faire :

```sh
$ ./exe Tikourbabine  
Bonjour Tikourbabine !
```

En compilant le programme, vous avez dû voir un avertissement de ce type s'afficher : 

```sh
$ gcc -g -m32 main.c -o exe 

main.c: In function ‘main’:
main.c:13:5: warning: format not a string literal and no format arguments [-Wformat-security]
   13 |     printf(argv[1]);
      |     ^~~~~~

```

**gcc** colère colère colère 😡. Et il a raison ! En effet, comme nous le dit si bien son manuel, le premier argument de `printf` est une **chaîne de format**. Une **chaîne de format** est bien plus **puissante**, et **dangereuse**, qu'une simple chaîne de caractères.

Amusons-nous encore un peu avec le programme fraîchement compilé :

```sh
$ ./exe p 
Bonjour p !
$ ./exe "%p"
Bonjour (nil) !
$ ./exe "%p %p %p"
Bonjour (nil) (nil) 0x583831b5 !
```

> Mais il n'y a qu'un seul argument donné à `printf(argv[1]);`, où est-ce que `%p` est allé chercher ces valeurs ?
{: .prompt-info }

C'est justement en découvrant la réponse à cette question que cela va devenir croustillant 😏. Pour cela, ouvrons le programme dans notre bon vieux **gdb** et mettons un point d'arrêt lors de l'appel à `printf` avec `argv[1]` :

![](/assets/images/introduction_au_pwn/bp_printf_bis.png)

> Le programme a été lancé avec `run "%p %p %p"`.
{: .prompt-tip }

Pour l'instant, rien de spécial. Jetons un œil au contenu de la pile juste **avant l'appel à** `printf` :

![](/assets/images/introduction_au_pwn/telescope_printf.png)

> **Astuce gdb** : la commande `telescope` permet d'afficher une zone mémoire sous forme de pointeurs en les déréférençant en chaîne. Elle est par défaut utilisable avec le pointeur de pile mais peut être également utilisée dans d'autres zones mémoire. 
{: .prompt-tip }

> Ce sont les valeurs affichées tout-à-l'heure dans `Bonjour (nil) (nil) 0x583831b5 !` ?
{: .prompt-info }

C'est ça ! `printf` ne connaît pas à l'avance **le nombre d'arguments** que va consommer la chaîne de format 🤷‍♂️. De ce fait, en fonction des spécificateurs de format et de leur nombre, nous allons pouvoir **afficher de plus en plus de valeurs** dans la pile de cette manière.

#### Utiliser `%p` en *pwn*

- 🎯 **Utilité** : afficher des valeurs lues sur la pile en hexadécimal

Il s'agit de l'un des spécificateurs les plus utilisés en *pwn*. Il permet de **récupérer** facilement des *leaks* **d'adresses mémoire**. 

Par exemple, il peut être utilisé pour récupérer des **fuites d'adresses** de la **libc**, du **tas**, de la **pile** ou bien de la section de code du **programme** en cours d'exécution.

De manière plus générale, il permet d'afficher une valeur en hexadécimal, que ce soit un **pointeur** ou **non**. Il peut, par exemple, être utilisé pour faire fuiter la **valeur du canari**.

### Afficher le contenu d'un pointeur avec `%s`

Tout d'abord, enlevons-nous de la tête le raccourci suivant : `%s` ne permet **que** d'afficher le contenu d'une **chaîne de caractère**. Cela est réducteur car `%s` permet plus généralement d'afficher le **contenu** de n'importe quel **pointeur**.

Il y a néanmoins **deux points** à noter :

- le pointeur doit **être valide** : pointer vers une zone mémoire accessible en lecture ;
- le contenu sera affiché jusqu'au **premier octet nul rencontré**.

Et si on testait notre programme avec `"%s"` ?

```sh
$ ./exe "%s"                  
Bonjour (null) !
```

On s'attendait à ce que le **programme plante** mais non, il nous a bien feinté ! En réalité donner un pointeur nul à `%s` est, selon le [standard du langage](https://www.trust-in-soft.com/resources/blogs/2019-07-09-printing-a-null-pointer-with-s-is-undefined-behavior), un [comportement indéfini](https://en.wikipedia.org/wiki/Undefined_behavior) mais généralement ce sera `"(null)"` qui sera affiché à la place.

Essayons d'afficher le contenu du troisième paramètre :

```sh
$ ./exe "%p %p %s" | xxd     
00000000: 426f 6e6a 6f75 7220 286e 696c 2920 286e  Bonjour (nil) (n
00000010: 696c 2920 [81c3 1f2e] 2021 0a              il) .... !.
```

Nous avons mis entre crochet le contenu qui a remplacé le spécificateur `%s`. C'est bien ce que l'on trouve dans **gdb** : 

![](/assets/images/introduction_au_pwn/tele_s.png)

Seuls les 4 premiers octets ont été affichés. Logique, me direz-vous ! `%s` affiche le contenu d'une chaîne de caractères et s'arrête donc au premier octet nul rencontré. C'est l'une des contraintes de ce spécificateur, mais on fait avec !

Pour résumer, `%p` a permis **d'afficher la valeur** du pointeur `0x565561b5` tandis que `%s` en a **affiché le contenu**. Ces deux spécificateurs sont donc **complémentaires**.

#### Utiliser `%s` en *pwn*

- 🎯 **Utilité** : afficher le contenu d'adresses en mémoire

Vous vous en doutez, `%s` est un spécificateur très utile en *pwn* car il permet d'afficher le **contenu d'un pointeur**. Attention tout de même à faire en sorte de lui fournir un pointeur valide, sinon le **programme plante**.

### Ecrire des valeurs grâce à `%n` 

Je pense que vous connaissiez déjà les deux précédents spécificateurs `%p` et notamment `%s`. Grâce à ces deux-là nous avons :

- un moyen **d'afficher des valeurs** en hexadécimal avec `%p` ;
- un moyen **d'afficher le contenu d'un pointeur** (jusqu'à tomber sur un octet nul) avec `%s`.

C'est très utile en *pwn* mais ça demeure de la **lecture en mémoire**. Lorsque l'on exploite un programme, nous avons également souvent besoin **d'écrire des valeurs** en mémoire.

Et là vous vous dites :

![](/assets/images/introduction_au_pwn/wat.png)

Oui oui il existe bien un spécificateur qui nous permettra de pouvoir **écrire des valeurs arbitraires** en mémoire, j'ai nommé : ✨`%n`✨.

L'utilité de `%n` selon `man 2 printf` est la suivante : `The  number  of  characters  written so far is stored into the integer pointed to by the corresponding argument.`.

J'sais pas vous, mais personnellement le terme `so far` m'a longtemps troublé pour comprendre ce qui se passe lorsque l'on utilise `%n`. 

En français, cela signifie que `%n` écrit dans l'argument idoine le **nombre d'octets qui ont déjà été écrits**, au moment où le programme arrive sur `%n`, après avoir substitué les spécificateurs par les valeurs adéquates. C'est toujours une définition bancale, je l'avoue.

Voyons donc concrètement comment cela fonctionne avec la ligne suivante :

```cpp
int val;
printf("Azertyu%n0123456789", &val);
```

`%n` va écrire le nombre d'octets qu'il y a avant lui dans `val`. Comme `"Azertyu"` est constituée de **7 octets**, la valeur `7` sera écrite dans la variable `val`. La fin de la chaîne formatée (`0123456789`) n'est pas utilisée car ce qui compte ce sont les octets affichés **avant** `%n`.

Et dans l'exemple suivant, que contiendra `%n` ?

```cpp
#include "stdio.h"

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("[-] Pas assez ou trop d'arguments.\n");
        return -1;
    }
    
	int val = 0;
	
	printf("salut %s !%n",argv[1], &val);
	printf("\nval : %d\n",val);
	
	return 0;
}
```

Le conteneur Docker :

- ⬇️ **Téléchargement** : [pwn-fmt-exemple-2.zip](https://drive.proton.me/urls/QXNW0T8T1C#Ssndks77IxUY)
- 🔎 **SHA256 & Analyse Virus Total** : [5a79ce2c1631e8174890346571a2600d65403fb313ca33200bc36bd56b317c8e](https://www.virustotal.com/gui/file/5a79ce2c1631e8174890346571a2600d65403fb313ca33200bc36bd56b317c8e)
- ⚙️ **Construction et lancement du conteneur** :

```sh
docker build -t pwn-fmt-exemple-2 .

docker run -it --rm -p 1234:1234 --cap-add=SYS_PTRACE --security-opt seccomp=unconfined pwn-fmt-exemple-2
```

Ce qui est sûr, c'est que l'on ne peut **pas le savoir à l'avance**, au moment de la compilation. En effet, comme cela a été dit précédemment, il faut d'abord que **tous les spécificateurs aient été substitués** avant de pouvoir compter le nombre d'octets affichés avant `%n`.

La valeur écrite dans `val` diffère en fonction du contenu de `argv[1]` :

```sh
$ ./exe aze
salut aze !
val : 11

$ ./exe azerty
salut azerty !
val : 14

$ ./exe aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
salut aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa !
val : 78
```

Concernant l’utilisation de `%n` pour effectuer **une écriture arbitraire**, vous commencez sans doute à en voir le potentiel 😏.

Allez, on attaque encore un exemple pour vérifier que vous avez bien saisi le principe de `%n` :

```cpp
#include "stdio.h"

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("[-] Pas assez ou trop d'arguments.\n");
        return -1;
    }
    
	int val = 0;
	int val_2 = 0;
	
	printf("salut %s !%n, tu vas bien ?%n",argv[1], &val,&val_2);
	printf("\nval : %d\n",val);
	printf("val_2 : %d\n",val_2);
	
	return 0;
}
```

Selon vous, quelle sera la valeur de `val_2` si le programme est lancé avec cette chaîne de caractères : `./exe aze` ? (sans exécuter le programme, bien sûr 😉 )

Réponse :

```
TGEgcsOpcG9uc2UgZXN0IDI2LiAKUG91ciBjb25uYcOudHJlIGxlIG5vbWJyZSBleGFjdCBkZSBjYXJhY3TDqHJlcyBhZmZpY2jDqXMgbG9yc3F1ZSBsZSBzZWNvbmQgYCVuYCBzZXJhIHRyYWl0w6ksIGlsIHN1ZmZpdCBkZSByZW1wbGFjZXIgdG91cyBsZXMgcHLDqWPDqWRlbnRzIHNww6ljaWZpY2F0ZXVycyAgcGFyIGxhIHZhbGV1ciBxdWkgbGVzIHJlbXBsYWNlIDoKCi0gYCVzYCAtPiAiYXplIiAoMyBjYXJhY3TDqHJlcykKLSBgJW5gIC0+IG4nZXN0IGphbWFpcyByZW1wbGFjw6kgcGFyIHVuZSB2YWxldXIgZW4gcGFydGljdWxpZXIgKCAwIGNhcmFjdMOocmUp
```

Le conteneur Docker pour tester:

- ⬇️ **Téléchargement** : [pwn-fmt-exemple-3.zip](https://drive.proton.me/urls/6A3TSCMB0G#DBGrJGOve7tv)
- 🔎 **SHA256 & Analyse Virus Total** : [b43b187232c4ed047b0e2b24f33425c69ece02c69004672f0da91617a51bfaf3](https://www.virustotal.com/gui/file/b43b187232c4ed047b0e2b24f33425c69ece02c69004672f0da91617a51bfaf3)
- ⚙️ **Construction et lancement du conteneur** :

```sh
docker build -t pwn-fmt-exemple-3 .

docker run -it --rm -p 1234:1234 --cap-add=SYS_PTRACE --security-opt seccomp=unconfined pwn-fmt-exemple-3
```

#### Utiliser `%n` en *pwn*

- 🎯 **Utilité** : écrire une valeur en mémoire

`%n` est le spécificateur par excellence pour **écrire des données** en mémoire en *pwn*. Il est possible de contrôler les données écrites en contrôlant le nombre de caractères qui seront déjà écrits dans la chaîne formatée, **après substitution** des spécificateurs.

Cela nous permet, certes, de contrôler ce que l'on écrit mais malheureusement, lorsque l'on doit écrire une **très grande valeur**, cela peut être **problématique**. 

Par exemple, imaginons que l'on ait besoin de modifier une valeur en mémoire avec la valeur `0xdeadbeef` (pour quelconque raison). Cela signifie qu'il va falloir au préalable faire en sorte de **remplir la chaîne formatée de** 3 735 928 559 octets (~3.7 Go !). Le programme risquera sûrement de planter lors d'une telle tentative 🤕.

Mais ne vous inquiétez pas, nous verrons une manière de contourner cette contrainte dans un chapitre ultérieur 😎.

## 📋 Synthèse

Ce chapitre introduit une nouvelle vulnérabilité qui est **l'utilisation détournée de chaînes de format**. Bien que cette vulnérabilité soit moins présente de nos jours, elle peut toujours être exploitée dans certaines configurations.

Nous avons vu les **3 principaux spécificateurs** utilisés en *pwn* pour exploiter les chaînes de format :

| Spécificateur | Utilité en pwn                                                                                                                   |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `%p`          | **Afficher des valeurs** (notamment des adresses) en hexadécimal lues sur la pile. Cela permet très souvent d'avoir des *leaks*. |
| `%s`          | **Afficher le contenu** d'un pointeur en mémoire (s'arrête au premier octet nul rencontré).                                      |
| `%n`          | **Ecrire des données** en mémoire.                                                                                               |

Lors du prochain chapitre, nous nous intéresserons à quelques fonctionnalités des chaînes de format, très utilisées en *pwn* à travers une série d'exercices.