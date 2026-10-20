# Base de données

Le stockage relationnel est proposé pour l'API et les métadonnées opérationnelles. Les migrations doivent être versionnées et exécutées par une procédure maîtrisée.

Principes :
- Lier les ressources à un tenant et à des identifiants opaques.
- Appliquer l'autorisation dans la couche métier ; envisager une défense supplémentaire au niveau SQL selon le moteur et le design.
- Ne pas stocker de secrets dans les colonnes applicatives en clair.
- Séparer métadonnées, preuves sensibles et logs opérationnels lorsque cela est nécessaire.
- Prévoir sauvegarde, rétention, accès opérateur et tests de restauration.
