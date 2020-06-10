
# Signals and Slots Implementation on Conflux

This directory hosts the bulk of the source code that implements signals and slots. Small parts of the original conflux source tree are also changed in order to support this feature. The purpose of this document is to outline how signals and slots are implemented and to keep track of the changes to the original source tree.

### Signals Implementation


### Changes to Conflux Source Tree
1. core/src/evm/: Added BINDSIG and EMITSIG to instructions.rs and interpreter/mod.rs to support new state changes.