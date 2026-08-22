---
title: Partie 23 - L'analyse dynamique - Le challenge de fin
date: 2023-10-08 10:00:00
categories: [Reverse, Introduction au reverse]
tags: [x86, reverse, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# Le challenge de fin

Nous avons vu énormément de choses jusqu'à présent et je suis sûr que vous avez peur d'oublier certaines notions, si ce n'est pas déjà le cas, et c'est normal.

Il est important de s'exercer afin de s'approprier tout ce que l'on a vu ensemble et que vous en gardiez des souvenirs afin de réutiliser vos connaissances plus tard.

Je vous propose donc un dernier *crackme*. Il ne s'agira pas, j'imagine, du dernier *crackme* que vous réaliserez mais celui-ci  devrait vous permettre de mettre en pratique ce que vous avez appris. Ce challenge devrait vous permettre :

- De mettre en pratique vos connaissances en **analyse statique**
- De mettre en pratique vos connaissances en **analyse dynamique**
- De découvrir quelques **protections anti-reverse**. Eh oui, pour l'instant tout fonctionnait à merveille et on avait quasiment aucun obstacle sur la route. Là, il va falloir passer entre les mailles du filet

Quelques conseils, à prendre ou à laisser :

- ✍️ N'hésitez pas à utiliser des **feuilles de brouillon** afin d'avoir une vue global sur le fonctionnement du programme.
- 💻 Lorsque vous ne comprenez pas certaines opérations dans le code décompilé, il peut être intéressant de le **reproduire en C, Python ou autre**.
- 🪜Afin de ne pas s'y perdre, il vaut mieux y aller **étape par étape**.
- 💡Plusieurs **indices** sont proposés afin de vous aider si vous vous sentez bloqués. Toutefois, les indices sont à consommer avec modération surtout que maintenant, vous êtes des pro du reverse !
- 🤔 Encore une fois, s'il y a des notions que vous n'avez jamais vues dans ce challenge, c'est le moment d'apprendre à se débrouiller dans un cas où l'on a pas toutes les cartes en main. Ce qui est vraiment cool avec le reverse est que l'on peut apprendre un tas de nouvelles choses en faisant des challenges !

### 💡 Indices 

Comme il ne s'agit pas d'un examen non plus, vous trouverez ci-dessous quelques indices pour avancer dans l'analyse lorsque vous êtes bloqués.

Il ne s'agit pas de réponse mais d'indications et de questions à se poser quant à l'analyse. 

💡 **Indice n°1**  

`UXVlIHByZW5kIGVuIGVudHLDqWUgY2UgcHJvZ3JhbW1lID8KQ29tbWVudCBzdWlzLWplIGNlbnPDqSBzYWlzaXIgbGUgZmxhZyA/ClF1J2VuIGVzdC1pbCBmYWl0ID8KQ29tbWVudCBkb2lzLWplLCBncm9zc28gbW9kbywgdmFsaWRlciBjZSBjaGFsbGVuZ2UgPw==`

💡 **Indice n°2**  

`SWwgcGV1dCB5IGF2b2lyIGRlcyBmb25jdGlvbnMgcXVpIGNvbnRpZW5uZW50IGRlIGwnYW50aS1kZWJ1ZywgaWwgZG9pdCBiaWVuIHkgYXZvaXIgdW4gbW95ZW4gZGUgbGVzIGNvbnRvdXJuZXIgc2FucyBxdSdlbGxlcyBub3VzIGFnYWNlbnQgw6AgY2hhcXVlIGZvaXMgLi4u`

💡 **Indice n°3**  

`UXVlbHMgc29udCBjZXMgYWxnb3JpdGhtZXMgcXVpIHNlbWJsZW50IMOqdHJlIHV0aWxpc8OpcyA/IApTb250LWlscyBpbnZlcnNpYmxlcyA/ClNpIG91aSA6IGNvbW1lbnQgbGUgaW52ZXJzZXIgPwpTaSBub24gOiBlc3QtY2UgcXVlIGxlIGZhaXQgcXUnaWwgbmUgc29pdCBwYXMgaW52ZXJzaWJsZSBwb3NlIHLDqWVsbGVtZW50IHByb2Jsw6htZSA/`

💡 **Indice n°4**  

`U2kgdm91cyBnYWzDqXJleiDDoCB0cm91dmVyIHF1ZWxzIHNvbnQgbGVzIGFsZ29yaXRobWVzIHV0aWxpc8OpcywgZXNzYXlleiBkZSBsZXMgcmVwcm9kdWlyZSBkYW5zIHVuIGJyb3VpbGxvbiBvdSBkYW5zIHVuIHNjcmlwdCBQeXRob24uCgpTYWNoZXogYXVzc2kgcXVlIGxlcyBhbGdvcml0aG1lcyB1dGlsaXNlbnQgZ8OpbsOpcmFsZW1lbnQgZGVzIGNvbnN0YW50ZXMgYmllbiBwcsOpY2lzZXMgcXVpIHBlcm1ldHRlbnQgbGUgZGVzIGlkZW50aWZpZXIgZW4gY2hlcmNoYW50IHVuIHBldSAuLi4=`


### 📄 Le programme

> Lorsque vous télécharger un programme et que vous souhaitez l'exécuter, prenez l'habitude de l'analyser avec un ou plusieurs anti-virus. Cela est particulièrement important sous Windows mais même sous Linux, il s'agit d'une bonne habitude à avoir.
> 
> Vous pouvez notamment utiliser [Virus Total](https://www.virustotal.com/gui/home/upload) en téléversant le programme à analyser (s'il n'est pas confidentiel) ou en le cherchant (s'il a déjà été téléversé auparavant) via son *hash* (ex: `sha256sum prgrm`).
{: .prompt-warning }

Vous pouvez télécharger le programme ici : [last_chall](https://drive.proton.me/urls/DE692Z2MAC#NNkFvRF0roam).

> Si vous rencontrez un problème dans le téléchargement ou exécution du challenge, n'hésitez pas à nous contacter à l'adresse : `reverse_zip[At]proton.me`.
{: .prompt-danger }

### 🎯 La solution

`TWFsaGV1cmV1c2VtZW50LCBkYW5zIGxhIHZyYWllIHZpZSwgb24gbmUgdm91cyBkb25uZXJhIHBhcyBsZXMgc29sdXRpb25zIGNvbW1lIMOnYSwgZMOpc29sw6kgIQoKQWxsZXosIGhvcCBob3AsIG9uIHkgcmV0b3VybmUgIQ==`
