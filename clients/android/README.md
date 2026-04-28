# VeilNode Android Client

This is the Android client scaffold. It keeps crypto in the shared `veil-core` boundary.

Production bridge target:

`Jetpack Compose App -> Storage Access Framework/FileProvider -> Android Keystore/StrongBox -> shared veil-core binding`.

Current scaffold documents the fixed-app + `.vpkg` import model and provides a minimal Compose shell source file.
