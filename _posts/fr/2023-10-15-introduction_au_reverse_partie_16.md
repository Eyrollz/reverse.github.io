---
title: Partie 16 - Le décompilateur - le challenge (3/3)
date: 2023-10-15 10:00:00
categories: [Reverse, Introduction au reverse]
tags: [x86, reverse, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# Le décompilateur : le challenge (crackme) (3/3)

## ℹ️ Le challenge

Nous y voilà ! Afin de nous familiariser avec IDA, quoi de mieux qu'un bon petit challenge !

Ce challenge est un *crackme*, il faudra donc trouver la bonne entrée pour le valider. Le challenge n'est ni trivial ni trop compliqué, il suffit d'y aller étape par étape en mettant en place un stratégie d'analyse.

Vous pouvez télécharger le challenge ici : [challenge](https://drive.proton.me/urls/7C62VVMFHM#lUinhCDXU5VV).

> Si vous rencontrez un programme dans le téléchargement ou exécution du challenge, n'hésitez pas à nous contacter à l'adresse : `reverse_zip[At]proton.me`.
{: .prompt-danger }

Quelques conseils (à prendre ou à laisser 🥹) :

- 👀 **L'analyse statique** est amplement suffisante pour réussir le challenge.
- ✍️ N'hésitez pas à utiliser des **feuilles de brouillon**, faire des schéma au fur et à mesure que vous avancez.
- 💻 Lorsque vous ne comprenez pas certaines opérations dans le code décompilé, il peut être intéressant de le **reproduire en C, Python ou autre**.
- 📄 Ne vous reposez pas seulement sur le code décompilé. Vous trouverez des mots clés utilisés par le décompilateur d'IDA qui sont liés au **code assembleur** utilisé.
- 🪜Afin de ne pas s'y perdre, il vaut mieux y aller **étape par étape**.
- 💡Plusieurs **indices** sont proposés afin de vous aider si vous vous sentez bloqués. Toutefois, les indices sont à consommer avec modération !
- 🤔 Il est possible qu'en avançant de fil en aiguille, que vous découvriez de nouvelles instructions, notions ou opérations dont on a pas encore parlé pour l'instant. Pas de panique ! C'est justement l'occasion d'apprendre à chercher des informations car en *reverse*, il arrive très souvent de tomber nez à nez face à de nouvelles notions qu'il faudra assimiler pour avancer dans l'analyse. Et puis, c'est ce qui fait le charme du *reverse* : **apprendre de nouvelles choses et ce, de manière ludique** !

## 💡 Les indices

💡 **Indice n°1**  

`UXUnYXR0ZW5kIGxlIHByb2dyYW1tZSBlbiBlbnRyw6llID8gCkNvbW1lbnQgZmFpdC1pbCwgZ3Jvc3NvIG1vZG8sIHBvdXIgdsOpcmlmaWVyIGwnZW50csOpZSA/IApRdWVsbGVzIHNvbnQgbGVzIGNvbnRyYWludGVzIHN1ciBsJ2VudHLDqWUgPyAKQ29tbWVudCBsZSBwcm9ncmFtbWUgZXN0LWlsIHN0cnVjdHVyw6kgPw==`

💡 **Indice n°2**  

`aHR0cHM6Ly9mci53aWtpcGVkaWEub3JnL3dpa2kvRmljaGllcjpBU0NJSS1UYWJsZS5zdmcKaHR0cHM6Ly9mci53aWtpcGVkaWEub3JnL3dpa2kvRm9uY3Rpb25fT1VfZXhjbHVzaWY=`

💡 **Indice n°3** 

`QXR0ZW50aW9uIGF1eCBjb252ZXJzaW9ucyBldCB0YWlsbGVzIGRlcyBkb25uw6llcyAhIEwnYXNzZW1ibGV1ciBwZXV0IGNvbnRlbmlyIGRlcyBpbmZvcm1hdGlvbnMgZGlmZmljaWxlbWVudCB2aXNpYmxlcyBkYW5zIGxhIGZlbsOqdHJlIGRlIGTDqWNvbXBpbGF0aW9uLg==`

💡 **Indice n°4**

`RGVzIGRlc3NpbnMsIGRlcyBkZXNzaW5zIGV0IGVuY29yZSBkZXMgZGVzc2lucyAhCgpBZmluIGRlIGJpZW4gbWHDrnRyaXNlciBsZXMgZMOpcGxhY2VtZW50IGRlIGJpdHMvb2N0ZXRzIGV0IGxldXIgbWFuaXB1bGF0aW9uLCBuJ2jDqXNpdGV6IHBhcyDDoCBmYWlyZSBkZXMgc2Now6ltYXMgc3VyIGZldWlsbGUgb3UgZGUgc2ltcGxlcyB0ZXN0cyBlbiBQeXRob24gYWZpbiBkZSB2w6lyaWZpZXIgcXVlIHZvdXMgYXZleiBiaWVuIGNvbXByaXMgY29tbWVudCBjZWxhIGZvbmN0aW9ubmUu`

## 🎯 La solution

`VkVkRloyTXlPWE5rV0ZKd1lqSTBaMXBZVGpCSlJHOW5aRVpXWms1R1RtWlpNVWt3VTNwT2VRPT0=`