---
title: Partie 3 - Fonctionnalités de base (bis)
date: 2023-09-04 10:00:00
categories: [Reverse, Introduction à l'exécution symbolique avec angr]
tags: [angr, Exécution symbolique]     # TAG names should always be lowercase
author: kabeche
toc: true
---
## Utiliser les hooks comme un pro 💪

Si vous n'avez pas la mémoire trop courte, vous devriez vous rappeler de la manière dont on avait utilisé un *hook*. Pour rappel on avait fait un truc du genre :

```python
p.hook(0x40113f, hook_atoi,5)
```

Cela permettait de *hooker* l'instruction `call atoi` (de taille 5 octets) afin que l'on puisse en **modifier le comportement via Python**. Cependant il y a d'autres cas d'usage dans lesquels on peut utiliser les *hooks*.

Par exemple, vous avez dû remarquer que lorsqu'un programme utilise `puts` ou `printf`, on ne voit jamais la chaîne de caractère affichée directement. Essayons de modifier ce comportement avec un *hook* grâce aux `SimProcedures` afin de toujours afficher le contenu de `puts`.

### Définir son propre *hook* via `SimProcedure`

Les `SimProcedures` permettent de faire du ***hooking* avancé** en ayant, par exemple, facilement accès aux arguments de la fonction *hookée*. 

Faisons un simple programme C qui réalise des appels successifs à `puts` :
```c++
#include <stdio.h>  
  
int main()  
{  
     puts("Salut");  
     puts("tout");  
     puts("le");  
     puts("monde !");  
     return 0;  
}
```

Si on exécute le programme avec angr jusqu'au `return`, on ne verra pas les chaînes de caractères dans notre terminal ( sauf si on trifouille dans `state.posix.dumps(sys.stdout.fileno())` pour avoir accès à l'*output*).

Avant de balancer tout le code en question, analysons ensemble le bout de code de *hook* afin de bien le comprendre :
```python
class MyPuts(angr.SimProcedure):  
     def run(self, addr_str):  
          #(...)

p.hook_symbol('puts', MyPuts())
```

> Dans les arguments de `hook` et `hook_symbol`, lorsqu'une classe dérivée de `SimProcedure` est utilisée, il faut absolument mettre les parenthèses sinon angr risque d'être ... angry 🙃
{: .prompt-warning }

Pour pouvoir utiliser les `SimProcedures`, il faut toujours déclarer sa classe dérivée de la sorte : `MaClasse(angr.SimProcedure)`. Cela permet par la suite d'avoir accès à certaines **fonctions pré-établies** telle que `run` qui est la fonction exécutée lorsque notre *hook* sera déclenché. 

Maintenant, il va bien falloir remplir cette fonction `run`, qu'allons-nous mettre ?

> Bah c'est simple on a qu'à faire `print(addr_str)` 🙄
{: .prompt-info }

Bien tenté mais cela ne fonctionnera pas ! En fait il faut voir l'argument `addr_str` comme l'argument de `puts` en C. Or l'argument de `puts` est une chaîne de caractère, plus précisément, **un pointeur vers une zone mémoire** contenant des caractères dont la fin est signalée par un octet nul.

Il va donc falloir bricoler un peu pour récupérer la chaîne de caractères à l'adresse `addr_str`. Rien de bien méchant, une boucle `for` et le tour est joué :
```python
class MyPuts(angr.SimProcedure):  
    def run(self, addr_str):  
        string = ""  
        # Récupération de la chaîne de caractère
        # en lisant octet par octet  
        for i in range(1000) :  
              val = self.state.memory.load(addr_str+i,1).concrete_value  
              # Fin de la chaîne  
              if val == 0 :  
                 break

              string += chr(val)  
        # Affichage de la chaîne  
        print(string)  
  
        return 0
```

Quelques remarques :
- On a accès à l'état courant via `self.state`
- On utilise le fameux `state.memory.load` pour lire en mémoire et récupérer les *bytes* de données à l'adresse `addr_str[i]` dans la boucle
- Lorsque l'on arrive à l'octet nul, c'est la fin de la chaîne de caractères 
- `range(1000)` est utilisé comme garde-fou pour ne pas tourner en rond indéfiniment

Le script final est celui-ci (attention **à modifier l'adresse** du `return` par celle de votre programme) :

```python
import angr  

# Initialisation du projet, état initial ...
p = angr.Project("./exe")  
main = p.loader.find_symbol("main")  
state_0 = p.factory.blank_state(addr= main.rebased_addr)  
sm = p.factory.simulation_manager(state_0)  
  
class MyPuts(angr.SimProcedure):  
     def run(self, addr_str):  
          string = ""  
          # Récupération de la chaîne de caractère  
          for i in range(1000) :  
               val = self.state.memory.load(addr_str+i,1).concrete_value  
               # Fin de la chaîne  
               if val == 0 :  
                         break  
                      
               string += chr(val)  
          # Affichage de la chaîne  
          print(string)  
  
          return 0  
       
p.hook_symbol('puts', MyPuts())  
  
# Adresse du 'return'  
sm.explore( find = 0x401193)
```

En exécutant ce script on voit bien dans le terminal lex chaînes de caractères attendues :
```
Salut  
tout  
le  
monde !
```

### Définir un hook avec un décorateur

Il est possible d'utiliser un décorateur Python pour définir un *hook*. Par exemple, pour le *hook* que l'on a déjà vu :
```python
p.hook(0x40113f, hook_atoi,5)
```

Il est possible de faire : 
```python
@project.hook(0x40113f, length=5)
def hook_atoi(state):
	# (...)
```

Cela permet de définir le *hook* **en même temps** que la fonction associée. C'est un peu plus joli et c'est plus lisible quand on lit le script.

Il est possible de définir plusieurs *hooks* en utilisant plusieurs décorateurs autour du *hook* associé. Cela est utile lorsqu'une fonction *hookée* est appelée à de maintes reprises dans le programme : 

```python
@project.hook(0x40113f, length=5)
@project.hook(0x409795, length=5)
def hook_atoi(state):
	# (...)
```

### Une histoire de symboles

Hooker des fonctions de la libc est chose aisée car :
- soit angr le fait déjà
- soit on a accès au symbole (et donc on peut récupérer l'adresse de la fonction via son nom) que le programme soit strippé ou non

Toutefois, lorsque le programme est **strippé** (les symboles des fonctions internes sont supprimés), on a **plus accès** au nom des fonctions internes. Même le `main` n'est plus accessible directement via son symbole avec `main = p.loader.find_symbol("main")` 😢.

Dans une telle situation, lorsque l'on veut *hooker* une fonction `fun_prgrm` du programme, on a deux manières de faire :

- Soit on sait exactement où est appelée cette fonction et il suffit de *hooker* toutes les instructions du type : `call fun_prgrm`
- Soit on ne sait pas où cela est fait et il va falloir *hooker* **toute** la fonction

On a déjà été confronté au premier cas, et on sait gérer. Mais comment faire alors si on se retrouve dans le second cas ?

Dans le second cas, il y a deux manières de faire :

1. **Utiliser un hook classique** : c'est **laborieux** car il faut calculer la taille de la fonction, sortir de la fonction nous même en modifiant `rip` avec la valeur idoine 🥱 ...
2. **Utiliser une classe dérivée de** `SimProcedure` : il s'agit de la méthode la **plus simple** car on n'aura pas besoin de calculer la taille de la fonction ni même besoin de retourner nous-même ; angr le fait déjà pour nous

#### Utiliser un hook classique

La première méthode peut être intéressante dans le cas où on veut modifier le comportement d'un **gros bloc de code** qui n'est pas une fonction appelée. Par exemple, si vous arrivez à identifier un bout de code qui fait de la détection anti-debug, *sleep* ou qui n'est pas très intéressant, vous pouvez simplement le *hooker* avec une fonction qui **ne fait rien** ( cela revient à "NOPer" tout le bout de code).

Exemple :

```python
# NOPer plusieurs instructions 
@p.hook(adresse_de_depart, length=taille_totale_des_instructions)
def nop(state):
	print("NOP")
```

#### Utiliser une classe dérivée de `SimProcedure`

La condition pour utiliser cette méthode est seulement de savoir où se situe la fonction que l'on souhaite *hooker* (appelons-la `fun_prgrm`). Ensuite on utilise une classe dérivée de `SimProcedure` et cette dernière se chargera toute seule de retourner comme il faut.

Par exemple, si `fun_prgrm` est située à `0x401149`, on peut faire :
```python
class MyFunc(angr.SimProcedure):
	def run(self):
		print("'fun_prgrm' hookée")
		# (...)
		return

p.hook(0x401149, MyFunc())
```


## Les limites d'angr

Après avoir vu les principales fonctionnalités qu'offre angr, vous vous dites sûrement que vous allez pouvoir enfin **démolir** tous les crackmes et **reverse bien plus aisément** n'importe quel programme. Eh bien malheureusement ce n'est pas aussi simple que cela car angr a tout de même pas mal de limitation 🫣 ...

![](/assets/images/introduction_a_l_execution_symbolique_avec_angr/meme_jimmy__.jpg)

### Moteur d'exécution codé en Python 🐍

L'une des **faiblesse majeure** d'angr face à d'autres outils d'exécution symbolique tels que [Triton](https://github.com/JonathanSalwan/Triton) ou [Binsec](https://github.com/binsec/binsec) est qu'il est codé totalement en **Python**.

Ainsi, même le moteur d'exécution est codé en Python contrairement à d'autres outils dont le Python est simplement un *wrapper* pour en faciliter l'utilisation.

Python c'est chouette, c'est simple mais qu'est-ce que c'est lent ^^' !

### L'explosion de chemin 💥

On en a brièvement parlé mais il s'agit d'**un des plus gros problèmes** de l'exécution symbolique. Cela ne concerne pas seulement angr mais n'importe quel moteur d'exécution symbolique.

Prenons un exemple concret pour voir comment va réagir angr lors d'une explosion de chemin.

Voici le code C que nous allons utiliser :
```c++
#include <stdio.h>

int un()
{
	return 1;
}
int zero()
{
	return 0;
}

int main()
{

	unsigned char data[16];
	printf("Enter 16 bytes of data: ");
	fread(data, sizeof(unsigned char), 16, stdin);
	
	for (int i = 0; i < 16; i++)
	{
		for (int j = 7; j >= 0; j--)
		{
			if ((data[i] >> j) & 1)
			{
				un();
			} 
			else
			{
				zero();
			}
		}
	}
	  
	return 0;
}
```

Il s'agit d'un code assez simple, son fonctionnement devrait vous être facile à comprendre.

Compilons-le avec `gcc main.c -o exe`. Maintenant, lançons angr sur le programme en lui donnant une adresse inatteignable lors de l'exploration :

```python
import angr
import IPython
import claripy
import os
import signal

# Code pour pouvoir ouvrir IPython
# avec Ctrl+C
def kill():
	current_pid = os.getpid()
	os.kill(current_pid, signal.SIGTERM)

def sigint_handler(signum, frame):
	print('Kill with : kill()')
	IPython.embed()

signal.signal(signal.SIGINT, sigint_handler)

p = angr.Project("./exe")
flag = claripy.BVS('flag', 16*8)

# On utilise 'rebased_addr' car le programme est compilé
# avec la protection PIE
main = p.loader.find_symbol("main")
state_0 = p.factory.blank_state(addr= main.rebased_addr,stdin=flag)
sm = p.factory.simulation_manager(state_0)

# Adresse inatteignable
print("Exploration en cours depuis le main")
sm.explore( find = 0xdeadbeef)
```

Plusieurs remarques :

- Le programme que l'on vient de compiler n'est pas *strippé* donc on a accès à tous les symboles, dont le symbole `main` via `p.loader.find_symbol("main")`
- Comme on a compilé le programme sans l'option `-no-pie`, le `main` est à l'*offset* `0x11a7`. Mais lors de l'exécution, il sera exécuté à une adresse aléatoire du type : `adresse_de_base_aleatoire + 0x11a7`, par exemple : `0x00005555555551af`. Ainsi, on utilise `main.rebased_addr` pour ne pas avoir à se préoccuper du PIE
- On insère le bout de code permettant d'ouvrir IPython avec `Ctrl+C`, cela nous sera utile !

En lançant le script Python, on constate qu'il consomme de plus en plus de mémoire. Initialement on a :
![](/assets/images/introduction_a_l_execution_symbolique_avec_angr/first.png)
Puis après quelques secondes / minutes d'exécution :
![](/assets/images/introduction_a_l_execution_symbolique_avec_angr/sec.png)

On constate de que le script consomme **énormément de mémoire** et comme on a pas envie que le PC finisse par *freeze* 🥶, on utilise l'arme fatale du Ctrl+C 🔫.

Un terminal IPython s'ouvre alors et on peut analyser ce qu'il se passe. Essayons de voir ce que contient le simulation manager qui, pour rappel, gère tous les états.

![](/assets/images/introduction_a_l_execution_symbolique_avec_angr/actives.png)

On voit que **1410 états sont actifs**, ce qui est **énorme** ! Déjà quand on en a plus d'une centaine faut commencer à se poser des questions, mais là c'est beaucoup trop !

Je vous conseille d'en finir avec le script en saisissant `kill()` dans le terminal IPython pour libérer les gigas de RAM occupées par le script.

Cet exemple vous permet de comprendre la principale limite de l'exécution symbolique à travers **l'explosion de chemins**.

### Les bibliothèques externes

Une autre faiblesse d'angr est qu'il **gère mal** les bibliothèques un peu complexes. Autant pour la libc certaines fonctions comme `printf`, `read` etc., ça, il sait faire. Autant des fonctions comme celles de l'API Windows, il galère davantage 🤕.

De ce fait, lorsque l'on analyse un programme Windows avec angr (par exemple, un *malware*), il va falloir *hooker* pas mal de fonction pour que le script n'aille pas dans les choux.

Cela ne veut pas dire qu'angr ne peut pas s'exécuter sur un programme Windows, c'est juste qu'il va falloir faire **plus attention** et faire plus d'analyse sur le code en amont avant d'entamer un script avec angr.

Je vous rassure, angr ne sert pas QUE pour la résolution de crackme. Il peut être utilisé pour désobfusquer certains programmes. On peut mentionner à ce titre la désobfuscation des [switch tables pour VM Protect](https://whereisr0da.github.io/blog/). 

### Quand utiliser angr ?

Pour conclure, je vous propose de lister les cas dans lesquels il peut être intéressant/facile d'utiliser angr et, *a contrario*, les cas dans lesquels ce n'est pas forcément la meilleure idée.

Evidemment, c'est une liste assez subjective et ce n'est pas parce que l'on a classé un cas dans ceux où il faut éviter d'utiliser angr que c'est une vérité absolu.

Dans l'idéal il s'agit de regarder au cas par cas l'objectif attendu et la manière dont est conçu le binaire ( programme, firmware ...) à analyser.

#### Les cas favorables ✅

- **Un crackme** qui utilise un algo assez linéaire avec des opérations simples (xor, add,sub ...)
- **Un programme Linux** : oui angr a un peu plus de mal avec les programmes Windows ( notamment les bibliothèques utilisées)
- **Un bout d'assembleur** : cela peut être une fonction ou simplement un bout de code désassemblé dont vous souhaitez comprendre le fonctionnment. angr permet en effet de charger directement de l'assembleur et de l'exécuter.
- **Désobfuscation classique** : sachez qu'il est possible de désobfusquer de manière efficace un programme avec angr. Cela demandera peut-être des notions avancées mais angr dispose d'un panel d'outils qui, utilisés ensemble, peuvent permettre de désobfusquer un programme. Cela étant, on parle ici d'obfuscation classique (switch table linéaire, prédicats opaques, MBA ...) et pas d'obfuscation poussée (switch tables non linéaires, nécessité d'exécuter en dynamique ...)

#### Les cas défavorables ⚠️

- **Les programmes Windows** : cf la raison plus haut. Evidemment cela ne veut pas dire qu'il n'est pas possible d'utiliser angr sur un *malware* (et c'est parfois utile d'ailleurs), mais c'est juste qu'il va falloir faire attention à la manière dont vous configurez angr.
- **Un programme qui fait trop souvent appel à des fonctions externes** : typiquement les programmes Windows qui font 1000 appels aux fonctions de l'API Windows
- **Programmes fortement obfusqués** avec de l'obfuscation très poussée
- **Programmes qui utilisent de la crypto** *state of the art* ( c'est pas demain qu'angr va casser AES :) ) 
