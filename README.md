# awesome-directed-fuzzing

Directed Fuzzing seems to be a current hot research topic. This repository aims to provide a curated list of research papers on directed whitebox/greybox fuzzing.

## Directed Whitebox Fuzzing
#### [ICSE'09] Taint-based Directed Whitebox Fuzzing [[paper]](https://people.csail.mit.edu/rinard/paper/icse09.pdf)

#### [S&P'10] TaintScope: A Checksum-Aware Directed Fuzzing Tool for Automatic Software Vulnerability Detection [[paper]](http://faculty.cs.tamu.edu/guofei/paper/TaintScope-Oakland10.pdf)

#### [SAS'11] Directed symbolic execution [[paper]](http://www.cs.tufts.edu/~jfoster/papers/sas11.pdf)

#### [ICSE'12] BugRedux: Reproducing Field Failures for In-house Debugging [[paper]]()

#### [Thesis'12] Hybrid Fuzz Testing: Discovering Software Bugs via Fuzzing and Symbolic Execution [[paper]](http://reports-archive.adm.cs.cmu.edu/anon/2012/CMU-CS-12-116.pdf)

#### [FSE'13] KATCH: High-Coverage Testing of Software Patches [[paper]](https://srg.doc.ic.ac.uk/files/papers/katch-fse-13.pdf)

#### [TOSEM'14] Directed Incremental Symbolic Execution [[paper]](https://userweb.cs.txstate.edu/~g_y10/publications/YangETAL14DiSE.pdf)

#### [ICSE'15] Hercules: Reproducing Crashes in Real-World Application Binaries [[paper]](https://thuanpv.github.io/publications/hercules.pdf)

#### [ICSE'16] Guiding Dynamic Symbolic Execution toward Unverified Program Executions [[paper]](https://www.microsoft.com/en-us/research/wp-content/uploads/2016/07/icse-2016.pdf)

#### [TASE'16] SeededFuzz: Selecting and Generating Seeds for Directed Fuzzing [[paper]](https://www.computer.org/csdl/proceedings-article/tase/2016/1764a049/12OmNAo45Pw)

#### [SAC'18] Improving Function Coverage with Munch: A Hybrid Fuzzing and Directed Symbolic Execution Approach [[paper]](https://arxiv.org/pdf/1711.09362.pdf) [[project]]()

## Directed Greybox Fuzzing
#### [CCS'17] Directed Greybox Fuzzing [[paper]](https://mboehme.github.io/paper/CCS17.pdf) [[project]](https://github.com/aflgo) [[slides]](https://www.slideshare.net/mboehme/aflgo-directed-greybox-fuzzing) [[talk]](https://www.youtube.com/watch?v=jiECNix0HuQ)

#### [CCS'18] Hawkeye: Towards a Desired Directed Grey-box Fuzzer [[paper]](https://hongxuchen.github.io/pdf/hawkeye.pdf) [[project]](https://sites.google.com/view/fot-the-fuzzer/DGF?authuser=0) [[slides]](https://hongxuchen.github.io/pdf/hawkeye-slides.pdf) [[talk]](https://www.youtube.com/watch?v=BSPj7GAQt5U&list=PLn0nrSd4xjjbyUeai0oevMrT8_IwnBo4R&index=7)

#### [DSN'19] 1dVul: Discovering 1-day Vulnerabilities through Binary Patches [[paper]](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=8809537)

#### [ICPC'19] Sequence coverage directed greybox fuzzing [[paper]](https://dl.acm.org/doi/10.1109/ICPC.2019.00044)

#### [CCS'19] Poster: Directed Hybrid Fuzzing on Binary Code [[paper]](https://dl.acm.org/doi/abs/10.1145/3319535.3363275)

#### [ICSE'19] LEOPARD: Identifying Vulnerable Code for Vulnerability Assessment through Program Metrics [[paper]](https://arxiv.org/pdf/1901.11479.pdf) [[project]](https://sites.google.com/site/leopardsite2017/)

#### [arxiv'19] V-Fuzz: Vulnerability-Oriented Evolutionary Fuzzing [[paper]](https://arxiv.org/pdf/1901.01142.pdf)

#### [SANER'20] Sequence directed hybrid fuzzing [[paper]](./sequence_hybrid.pdf)

#### [ICSE'20] Targeted Greybox Fuzzing with Static Lookahead Analysis [[paper]](https://mariachris.github.io/Pubs/ICSE-2020.pdf)

#### [SEC'20] FuzzGuard: Filtering out Unreachable Inputs in Directed Grey-box Fuzzing through Deep Learning [[paper]](http://kaichen.org/paper/conference/sec20summer-final343.pdf) [[project]](https://github.com/zongpy/FuzzGuard)

#### [SEC'20] ParmeSan: Sanitizer-guided Greybox Fuzzing [[paper]](https://download.vusec.net/papers/parmesan_sec20.pdf) [[project]](https://github.com/vusec/parmesan) [[my slides]](./ParmeSan.pdf)

#### [arxiv'20] Binary-level Directed Fuzzing for Use-After-Free Vulnerabilities [[paper]](https://arxiv.org/pdf/2002.10751.pdf)

#### [arxiv'20] TOFU: Target-Oriented FUzzer [[paper]](https://arxiv.org/pdf/2004.14375.pdf)
- *Command-line flags*: TOFU augments the input space that it explores to include command-line flags, so that users do not have to select such flags manually.
- *Distance metric*: the number of correct branching decisions needed to reach the target, and does not use a complicated relationship to the history of the annealing that has taken place (e.g., min-max normalized values)
- *Input-structure aware*: TOFU leverages knowledge of the program’s input structure in the form of a protobuf
specification.

## Others
#### [ISSTA'11] Statically-Directed Dynamic Automated Test Generation [[paper]](http://bitblaze.cs.berkeley.edu/papers/testgen-issta11.pdf)

#### [SEC'13] Dowsing for overflows: A guided fuzzer to find buffer boundary violations [[paper]](https://www.cs.vu.nl/~herbertb/papers/dowser_usenixsec13.pdf)

#### [ASPLOS'15] Targeted Automatic Integer Overflow Discovery Using Goal-Directed Conditional Branch Enforcement [[paper]](https://people.csail.mit.edu/fanl/papers/diode-asplos2015.pdf)

#### [PLDI'19] Parser-Directed Fuzzing [[paper]](https://rahul.gopinath.org/resources/pldi2019/mathis2019parser.pdf) [[project]](https://drive.google.com/drive/folders/1OAgT9DPe_Nr2NI32KypK1sqmM0u1EYlQ) [[video]](https://www.youtube.com/watch?v=ypwppYHSz6A)
