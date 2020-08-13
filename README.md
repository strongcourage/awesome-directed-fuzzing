# awesome-directed-fuzzing

Directed Fuzzing seems to be a current hot research topic. This repository aims to provide a curated list of research papers focusing on directed greybox fuzzing (see more [directed whitebox fuzzing](./whitebox.md) and [miscellaneous](./misc.md)).

## Directed Greybox Fuzzing
#### [CCS'17] Directed Greybox Fuzzing [[paper]](https://mboehme.github.io/paper/CCS17.pdf) [[project]](https://github.com/aflgo) [[slides]](https://www.slideshare.net/mboehme/aflgo-directed-greybox-fuzzing) [[talk]](https://www.youtube.com/watch?v=jiECNix0HuQ)

#### [CCS'18] Hawkeye: Towards a Desired Directed Grey-box Fuzzer [[paper]](https://hongxuchen.github.io/pdf/hawkeye.pdf) [[project]](https://sites.google.com/view/fot-the-fuzzer/DGF?authuser=0) [[slides]](https://hongxuchen.github.io/pdf/hawkeye-slides.pdf) [[talk]](https://www.youtube.com/watch?v=BSPj7GAQt5U&list=PLn0nrSd4xjjbyUeai0oevMrT8_IwnBo4R&index=7)

#### [DSN'19] 1dVul: Discovering 1-day Vulnerabilities through Binary Patches [[paper]](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=8809537)

#### [ICPC'19] Sequence coverage directed greybox fuzzing [[paper]](https://dl.acm.org/doi/10.1109/ICPC.2019.00044)

#### [CCS'19] Poster: Directed Hybrid Fuzzing on Binary Code [[paper]](https://dl.acm.org/doi/abs/10.1145/3319535.3363275)

#### [ICSE'19] LEOPARD: Identifying Vulnerable Code for Vulnerability Assessment through Program Metrics [[paper]](https://arxiv.org/pdf/1901.11479.pdf) [[project]](https://sites.google.com/site/leopardsite2017/)

#### [arxiv'19] V-Fuzz: Vulnerability-Oriented Evolutionary Fuzzing [[paper]](https://arxiv.org/pdf/1901.01142.pdf)

#### [SANER'20] Sequence directed hybrid fuzzing [[paper]](./sequence_hybrid.pdf)

#### [ICSE'20] Targeted Greybox Fuzzing with Static Lookahead Analysis [[paper]](https://mariachris.github.io/Pubs/ICSE-2020.pdf) [[talk]](https://www.youtube.com/watch?v=86vvChVr9bQ)

#### [SEC'20] FuzzGuard: Filtering out Unreachable Inputs in Directed Grey-box Fuzzing through Deep Learning [[paper]](http://kaichen.org/paper/conference/sec20summer-final343.pdf) [[project]](https://github.com/zongpy/FuzzGuard) [[slides]](https://www.usenix.org/system/files/sec20_slides_zong.pdf) [[talk]](https://www.usenix.org/conference/usenixsecurity20/presentation/zong)

#### [SEC'20] ParmeSan: Sanitizer-guided Greybox Fuzzing [[paper]](https://download.vusec.net/papers/parmesan_sec20.pdf) [[project]](https://github.com/vusec/parmesan) [[slides]](https://www.usenix.org/system/files/sec20_slides_osterlund.pdf) [[talk]](https://www.usenix.org/conference/usenixsecurity20/presentation/osterlund)

#### [RAID'20] Binary-level Directed Fuzzing for Use-After-Free Vulnerabilities [[paper]](https://arxiv.org/pdf/2002.10751.pdf) [[project]](https://github.com/strongcourage/uafuzz)

#### [arxiv'20] TOFU: Target-Oriented FUzzer [[paper]](https://arxiv.org/pdf/2004.14375.pdf)
- *Command-line flags*: TOFU augments the input space that it explores to include command-line flags, so that users do not have to select such flags manually.
- *Distance metric*: the number of correct branching decisions needed to reach the target, and does not use a complicated relationship to the history of the annealing that has taken place (e.g., min-max normalized values)
- *Input-structure aware*: TOFU leverages knowledge of the program’s input structure in the form of a protobuf
specification.

#### [arxiv'20] SoK: The Progress, Challenges, and Perspectives of Directed Greybox Fuzzing [[paper]](https://arxiv.org/pdf/2005.11907.pdf)
