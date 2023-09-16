---
title: Partie 4 - En apprendre toujours plus
date: 2023-09-05 10:00:00
categories: [Reverse, Introduction à l'exécution symbolique avec angr]
tags: [angr, Exécution symbolique]     # TAG names should always be lowercase
author: kabeche
toc: true
---
# Apprendre à se documenter

Nous avons pu voir ensemble plusieurs fonctionnalités de **base** que propose angr, de l'utilisation du solveur à l'implémentation de *hooks* en passant par la gestion de l'entrée et sortie standards.

Toutefois, il ne sera malheureusement pas possible de couvrir en un cours toutes les fonctionnalités d'angr dont certaines sont très intéressantes :

- Utilisation de la **représentation en graphe** des [*basic blocks*](https://fr.wikipedia.org/wiki/Bloc_de_base)
- **Exécution concolique**
- **Plugins** d'angr dans différents programmes : plugin Ida Python, plugin gdb ...

Certaines feront peut-être l'objet d'un prochain cours dédié aux fonctionnalités avancées d'angr, si Dieu le veut. 

En attendant, il faut absolument que vous sachiez vous documenter concernant l'utilisation d'angr. Pour cela, plusieurs méthodes sont possibles.

### La documentation officielle d'angr

Bah pour se documenter, on peut déjà utiliser la doc'.

![](/assets/images/introduction_a_l_execution_symbolique_avec_angr/merci_sherlock.png)

La **documentation officielle** d'angr se situe à cette adresse: [docs.angr.io](docs.angr.io). Le site est assez intuitif, il suffit d'utiliser la **barre de recherche** pour chercher un attribut, une méthode (fonction) ou classe afin d'avoir plus de détails.

Concernant les méthodes, la documentation donne notamment les différents paramètres que l'on peut utiliser lors de l'appel de la fonction. Par exemple, si je veux savoir quels sont les différents paramètres que l'on peut utiliser lors de la création d'un `entry_state`, il suffit de saisir :


![](/assets/images/introduction_a_l_execution_symbolique_avec_angr/search_documentation.png)

En cliquant sur le premier lien, on obtient la description des différents arguments utilisables :

![](/assets/images/introduction_a_l_execution_symbolique_avec_angr/args_entry_state.png)

> C'est normal que le site soit très lent ?
{: .prompt-info }

Oui malheureusement le site **assez lent** lorsque l'on fait des recherche... J'ai l'impression que le souci est que la page charge longtemps. Je vous conseille de stopper le chargement de la page une fois que celle-ci semble être chargée correctement puis de faire un Ctrl+F sur la fonction (ou autre) recherchée.

### Utiliser IPython

On en a déjà parlé je ne vais pas refaire une partie à ce sujet, je vous invite à relire le chapitre concerné si vous avez besoin de vous rafraîchir la mémoire ;).

Néanmoins, je souhaite tout de même rappeler que dans un terminal IPython, lorsque l'on saisit une expression du style `objet.` puis que vous appuyez sur TAB, cela vous affichera les **méthodes** et **attributs** de l'objet en question.

### Utiliser un moteur de recherche spécialisé dans la recherche de code

C'est une **méthode de recherche** dont j'ai appris l'existence que très tard malheureusement (merci CharlB au passage). 

Cette méthode est basée sur l'utilisation de sites, plus précisément **moteurs de recherche**, qui vont retourner des résultats liés à votre recherche en naviguant dans les dépôts **GitHub**.

Evidemment, cette méthode n'est pas seulement utilisable avec angr mais n'importe quel type de code (fonction, classe, structure ...) dont vous souhaitez avoir des détails.

Voici les deux principaux (il y en a sûrement d'autres) :

- [grep.app](https://grep.app/) : Le site est plutôt bien fait et permet généralement de trouver ce que l'on cherche. Il est également possible de filtrer par type de fichier ( `.py`, `.c`, `.yml` ...)
- [sourcegraph.com](sourcegraph.com) : Le site est également assez ergonomique. Il peut être utilisé en complément à **grep.app** car il réussit parfois à trouver ce que l'on cherche dans des dépôts où **grep.app** n'a pas navigué

En utilisant **grep.app** pour chercher des informations concernant `entry_state`, voici ce que l'on peut obtenir comme résultats :
![](/assets/images/introduction_a_l_execution_symbolique_avec_angr/grep_app_result.png)

Voilà ! Vous n'avez plus d'excuses pour ne pas devenir des pros d'angr !

### Utiliser ChatGPT

ChatGPT est très utile pour créer des scripts angr. Je trouve que les scripts qu'il génère sont globalement bien faits même si, évidemment, il faut souvent faire une passe derrière.

En revanche, si on lui demande un script beaucoup trop complexe il risque de se planter et on risque de perdre encore plus de temps à comprendre d'où vient le bug dans le script.

Néanmoins pour des scripts basiques ou pour des commandes dont on a oublié l'utilisation, c'est vraiment très utile ( exemple si on a oublié comment faire de la lecture/écriture en mémoire : `Fais moi un script qui lit 10 octets à telle adresse puis écrit 8 octets à telle autre adresse, le tout en little endian`).

Il faut donc voir ChatGPT comme un outil qui permet de poser, grosso modo, les premières briques de notre script qu'il va falloir finir à la mano. Lui demander des choses trop complexes, est, à mon sens, risqué car il est possible de perdre plus de temps à le corriger qu'en faisant le script soi-même.