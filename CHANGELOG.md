# Journal des versions

## 1.0.1 — 18 octobre 2026

### Mises à jour
- L’image passe de Python 3.11 à **Python 3.14** (image de base toujours figée par empreinte).
- Composants de publication GitHub en nouvelle version majeure : connexion au registre, métadonnées, émulation et construction multi-plateforme.

### Tests
- Les réponses HTTP d’erreur des tests sont refermées proprement.

## 1.0.0 — 18 octobre 2026

Première version partageable.

### Nouveautés
- **Carte réseau orbitale** (ordinateur et tablette) : Livebox au centre, répéteurs avec leur propre système, appareils en orbite par liaison, flux animés selon le débit, détails au clic, zoom à la molette ou au pincement, plein écran. Arborescence repliable sur téléphone.
- **Topologie réelle** lue dans la Livebox : port Ethernet, bande Wi-Fi et répéteur de chaque appareil.
- **Reconnaissance des appareils** : fabricant (registre IEEE), modèle annoncé, catégorie suggérée avec ses raisons ; jamais appliquée sans votre accord. Les e-mails « nouvel équipement » indiquent ce que l’appareil est probablement.
- **Journal des connexions** regroupé par jour ou par appareil, avec la durée de présence ou d’absence, pagination par 20, 50 ou 100.

### Améliorations
- Champs de formulaire de même hauteur et de même style partout (tableau de bord, journal, fiche équipement).
- `PUBLIC_URL` pour les liens des e-mails ; valeurs par défaut neutres.
- `compose.yaml` standard (port publié, vérification de santé) ; image pour `amd64` et `arm64`.

### Corrections
- Sur iPhone (Safari, Firefox), la session n’était pas conservée : le cookie est désormais `SameSite=Lax` et la page de connexion ne l’efface plus.

### Sécurité
- Le compte ne peut pas être créé avec le mot de passe d’exemple ou un mot de passe de moins de 12 caractères.
- Les mots de passe enregistrés (Livebox, SMTP) ne sont jamais envoyés vers une autre adresse sans être ressaisis ; ports SMTP limités à 25, 465, 587 et 2525 ; erreurs réseau génériques.
- Même message d’erreur de connexion, que le mot de passe ou le code soit faux ; désactiver le second facteur ferme les autres sessions ; la limitation des tentatives ne bloque plus le propriétaire.
- Le script de restauration est livré avec Sentinel (`tools/restore.sh`) et efface les sessions de la sauvegarde ; la description de l’API n’est plus publiée.
- Versions figées : image de base, LiveboxMonitor, dépendances Python et actions GitHub ; mises à jour proposées par Dependabot.

### Organisation
- Code dans `sentinel/`, outils dans `tools/`, tests dans `tests/unit` et `tests/browser`.
