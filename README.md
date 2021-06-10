# awesome-directed-fuzzing

Directed Fuzzing seems to be a current hot research topic. This repository aims to provide a curated list of research papers focusing on directed greybox fuzzing (see more [directed whitebox fuzzing](./whitebox.md) and [miscellaneous](./misc.md)).

## Directed Greybox Fuzzing
#### [CCS'17] Directed Greybox Fuzzing 

[[paper]](https://mboehme.github.io/paper/CCS17.pdf) [[project]](https://github.com/aflgo) [[slides]](https://www.slideshare.net/mboehme/aflgo-directed-greybox-fuzzing) [[talk]](https://www.youtube.com/watch?v=jiECNix0HuQ)

<details>
  <summary>Click to see the abstract!</summary>
Existing Greybox Fuzzers (GF) cannot be effectively directed, for instance, towards problematic changes or patches, towards critical system calls or dangerous locations, or towards functions in the stacktrace of a reported vulnerability that we wish to reproduce. In this paper, we introduce Directed Greybox Fuzzing (DGF) which generates inputs with the objective of reaching a given set of target program locations efficiently. We develop and evaluate a simulated annealing-based power schedule that gradually assigns more energy to seeds that are closer to the target locations while reducing energy for seeds that are further away. Experiments with our implementation AFLGo demonstrate that DGF outperforms both directed symbolic-execution-based whitebox fuzzing and undirected greybox fuzzing. We show applications of DGF to patch testing and crash reproduction, and discuss the integration of AFLGo into Google’s continuous fuzzing platform OSS-Fuzz. Due
to its directedness, AFLGo could find 39 bugs in several well-fuzzed, security-critical projects like LibXML2. 17 CVEs were assigned.
</details>

#### [CCS'18] Hawkeye: Towards a Desired Directed Grey-box Fuzzer 

[[paper]](https://hongxuchen.github.io/pdf/hawkeye.pdf) [[project]](https://sites.google.com/view/fot-the-fuzzer/DGF?authuser=0) [[slides]](https://hongxuchen.github.io/pdf/hawkeye-slides.pdf) [[talk]](https://www.youtube.com/watch?v=BSPj7GAQt5U&list=PLn0nrSd4xjjbyUeai0oevMrT8_IwnBo4R&index=7)

<details>
  <summary>Click to see the abstract!</summary>
Grey-box fuzzing is a practically effective approach to test realworld programs. However, most existing grey-box fuzzers lack directedness, i.e. the capability of executing towards user-specified target sites in the program. To emphasize existing challenges in directed fuzzing, we propose Hawkeye to feature four desired properties of directed grey-box fuzzers. Owing to a novel static analysis on the program under test and the target sites, Hawkeye precisely collects the information such as the call graph, function and basic block level distances to the targets. During fuzzing, Hawkeye evaluates exercised seeds based on both static information and the execution traces to generate the dynamic metrics, which are then used for seed prioritization, power scheduling and adaptive mutating.
These strategies help Hawkeye to achieve better directedness and gravitate towards the target sites. We implemented Hawkeye as a fuzzing framework and evaluated it on various real-world programs under different scenarios. The experimental results showed that Hawkeye can reach the target sites and reproduce the crashes much faster than state-of-the-art grey-box fuzzers such as AFL and AFLGo. Specially, Hawkeye can reduce the time to exposure for certain vulnerabilities from about 3.5 hours to 0.5 hour. By now, Hawkeye has detected more than 41 previously unknown crashes in projects such as Oniguruma, MJS with the target sites provided by vulnerability prediction tools; all these crashes are confirmed and 15 of them have been assigned CVE IDs.
</details>

#### [DSN'19] 1dVul: Discovering 1-day Vulnerabilities through Binary Patches 

[[paper]](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=8809537)

<details>
  <summary>Click to see the abstract!</summary>
Discovering 1-day vulnerabilities in binary patches is worthwhile but challenging. One of the key difficulties lies in generating inputs that could reach the patched code snippet while making the unpatched program crash. In this paper, we named it as a target-oriented input generation problem or a ToIG problem for clarity. Existing solutions for the ToIG problem either suffer from path explosion or may get stuck by complex checks. In the paper, we present a new solution to improve the efficiency of ToIG which leverage a combination of a distance-based directed fuzzing mechanism and a dominator-based directed symbolic execution mechanism. To demonstrate its efficiency, we design and implement 1dVul, a tool for 1-day vulnerability discovering at binary-level, based on the solution. Demonstrations show that 1dVul has successfully generated inputs for 130 targets from a total of 209 patch targets identified from applications in DARPA Cyber Grant Challenge, while the state-of-the-art solutions AFLGo and Driller can only reach 99 and 107 targets, respectively, within the same limited time budget. Further-more, 1dVul runs 2.2X and 3.6X faster than AFLGo and Driller, respectively, and has confirmed 96 vulnerabilities from the unpatched programs.
</details>

#### [ICPC'19] Sequence coverage directed greybox fuzzing 

[[paper]](https://dl.acm.org/doi/10.1109/ICPC.2019.00044)

<details>
  <summary>Click to see the abstract!</summary>
Existing directed fuzzers are not efficient enough. Directed symbolic-execution-based whitebox fuzzers, e.g. BugRedux, spend lots of time on heavyweight program analysis and constraints solving at runtime. Directed greybox fuzzers, such as AFLGo, perform well at runtime, but considerable calculation during instrumentation phase hinders the overall performance.

In this paper, we propose Sequence-coverage Directed Fuzzing (SCDF), a lightweight directed fuzzing technique which explores towards the user-specified program statements efficiently. Given a set of target statement sequences of a program, SCDF aims to generate inputs that can reach the statements in each sequence in order and trigger bugs in the program. Moreover, we present a novel energy schedule algorithm, which adjusts on demand a seed's energy according to its ability of covering the given statement sequences calculated on demand. We implement the technique in a tool LOLLY in order to achieve efficiency both at instrumentation time and at runtime. Experiments on several real-world software projects demonstrate that LOLLY outperforms two well-established tools on efficiency and effectiveness, i.e., AFLGo-a directed greybox fuzzer and BugRedux-a directed symbolic-execution-based whitebox fuzzer.
</details>

#### [CCS'19] Poster: Directed Hybrid Fuzzing on Binary Code 

[[paper]](https://dl.acm.org/doi/abs/10.1145/3319535.3363275)

<details>
  <summary>Click to see the abstract!</summary>
Hybrid fuzzers combine both fuzzing and concolic execution with the wish that the fuzzer will quickly explore input spaces and the concolic execution will solve the complex path conditions. However, existing hybrid fuzzers such as Driller cannot be effectively directed, for instance, towards unsafe system calls or suspicious locations, or towards functions in the call stack of a reported vulnerability that we wish to reproduce. In this poster, we propose DrillerGO, a directed hybrid fuzzing system, to mitigate this problem. It mainly consists of a static analysis and a dynamic analysis module. In the static analysis, it searches suspicious API call strings in the recovered control flow graph (CFG). After targeting some suspicious API call lines, it runs the concolic execution along with path guiding. The path guiding is helped by backward pathfinding, which is a novel technique to find paths backward from the target to the start of main(). Also, we will show that DrillerGo can find the crashes faster than Driller through experimental results.
</details>

#### [ICSE'19] LEOPARD: Identifying Vulnerable Code for Vulnerability Assessment through Program Metrics 

[[paper]](https://arxiv.org/pdf/1901.11479.pdf) [[project]](https://sites.google.com/site/leopardsite2017/)

<details>
  <summary>Click to see the abstract!</summary>
Identifying potentially vulnerable locations in a code base is critical as a pre-step for effective vulnerability assessment; i.e., it can greatly help security experts put their time and effort to where it is needed most. Metric-based and pattern-based methods have been presented for identifying vulnerable code. The former relies on machine learning and cannot work well due to the severe imbalance between non-vulnerable and vulnerable code or lack of features to characterize vulnerabilities. The latter needs the prior knowledge of known vulnerabilities and can only identify similar but not new types of vulnerabilities.

In this paper, we propose and implement a generic, lightweight and extensible framework, LEOPARD, to identify potentially vulnerable functions through program metrics. LEOPARD requires no prior knowledge about known vulnerabilities. It has two steps by combining two sets of systematically derived metrics. First, it
uses complexity metrics to group the functions in a target application into a set of bins. Then, it uses vulnerability metrics to rank the functions in each bin and identifies the top ones as potentially vulnerable. Our experimental results on 11 real-world projects have demonstrated that, LEOPARD can cover 74.0% of vulnerable functions by identifying 20% of functions as vulnerable and outperform machine learning-based and static analysis-based techniques. We further propose three applications of LEOPARD for manual code review and fuzzing, through which we discovered 22 new bugs in real applications like PHP, radare2 and FFmpeg, and eight of them are new vulnerabilities.
</details>

#### [arxiv'19] V-Fuzz: Vulnerability-Oriented Evolutionary Fuzzing 

[[paper]](https://arxiv.org/pdf/1901.01142.pdf)

<details>
  <summary>Click to see the abstract!</summary>
Fuzzing is a technique of finding bugs by executing a software recurrently with a large number of abnormal inputs. Most of the existing fuzzers consider all parts of a software equally, and pay too much attention on how to improve the code coverage. It is inefficient as the vulnerable code only takes a tiny fraction of the entire code. In this paper, we design and implement a vulnerability-oriented evolutionary fuzzing prototype named V-Fuzz, which aims to find bugs efficiently and quickly in a limited time. V-Fuzz consists of two main components: a neural network-based vulnerability prediction model and a vulnerability-oriented evolutionary fuzzer. Given a binary program to V-Fuzz, the vulnerability prediction model will give a prior estimation on which parts of the software are more likely to be vulnerable. Then, the fuzzer leverages an evolutionary algorithm to generate inputs which tend to arrive at the vulnerable locations, guided by the vulnerability prediction result. Experimental results demonstrate that V-Fuzz can find bugs more efficiently than state-of-the-art fuzzers. Moreover, V-Fuzz has discovered 10 CVEs, and 3 of them are newly discovered. We reported the new CVEs, and they have been confirmed and fixed.
</details>

#### [SANER'20] Sequence directed hybrid fuzzing 

[[paper]](./sequence_hybrid.pdf)

<details>
  <summary>Click to see the abstract!</summary>

</details>

#### [ICSE'20] Targeted Greybox Fuzzing with Static Lookahead Analysis 

[[paper]](https://mariachris.github.io/Pubs/ICSE-2020.pdf) [[talk]](https://www.youtube.com/watch?v=86vvChVr9bQ)

<details>
  <summary>Click to see the abstract!</summary>
Automatic test generation typically aims to generate inputs that explore new paths in the program under test in order to find bugs. Existing work has, therefore, focused on guiding the exploration toward program parts that are more likely to contain bugs by using an offline static analysis. In this paper, we introduce a novel technique for targeted greybox fuzzing using an online static analysis that guides the fuzzer toward a set of target locations, for instance, located in recently modified parts of the program. This is achieved by first semantically analyzing each program path that is explored by an input in the fuzzer’s test suite. The results of this analysis are then used to control the fuzzer’s specialized power schedule, which determines how often to fuzz inputs from the test suite. We implemented our technique by extending a state-of-the-art, industrial fuzzer for Ethereum smart contracts and evaluate its effectiveness on 27 real-world benchmarks. Using an online analysis is particularly suitable for the domain of smart contracts since it does not require any code instrumentation-adding instrumentation to contracts changes their semantics. Our experiments show that targeted fuzzing significantly outperforms standard greybox fuzzing for reaching 83% of the challenging target locations (up to 14x of median speed-up).
</details>

#### [SEC'20] FuzzGuard: Filtering out Unreachable Inputs in Directed Grey-box Fuzzing through Deep Learning 

[[paper]](http://kaichen.org/paper/conference/sec20summer-final343.pdf) [[project]](https://github.com/zongpy/FuzzGuard) [[slides]](https://www.usenix.org/system/files/sec20_slides_zong.pdf) [[talk]](https://www.usenix.org/conference/usenixsecurity20/presentation/zong)

<details>
  <summary>Click to see the abstract!</summary>
Recently, directed grey-box fuzzing (DGF) becomes popular in the field of software testing. Different from coverage-based fuzzing whose goal is to increase code coverage for triggering more bugs, DGF is designed to check whether a piece of potentially buggy code (e.g., string operations) really contains a bug. Ideally, all the inputs generated by DGF should reach the target buggy code until triggering the bug. It is a waste of time when executing with unreachable inputs. Unfortunately, in real situations, large numbers of the generated inputs cannot let a program execute to the target, greatly impacting the efficiency of fuzzing, especially when the buggy code is embedded in the code guarded by various constraints. 
  
In this paper, we propose a deep-learning-based approach to predict the reachability of inputs (i.e., miss the target or not) before executing the target program, helping DGF filtering out the unreachable ones to boost the performance of fuzzing. To apply deep learning with DGF, we design a suite of new techniques (e.g., step-forwarding approach, representative data selection) to solve the problems of unbalanced labeled data and insufficient time in the training process. Further, we implement the proposed approach called FuzzGuard and equip it
with the state-of-the-art DGF (e.g., AFLGo). Evaluations on 45 real vulnerabilities show that FuzzGuard boosts the fuzzing efficiency of the vanilla AFLGo up to 17.1×. Finally, to understand the key features learned by FuzzGuard, we illustrate their connection with the constraints in the programs
</details>

#### [SEC'20] ParmeSan: Sanitizer-guided Greybox Fuzzing 

[[paper]](https://download.vusec.net/papers/parmesan_sec20.pdf) [[project]](https://github.com/vusec/parmesan) [[slides]](https://www.usenix.org/system/files/sec20_slides_osterlund.pdf) [[talk]](https://www.usenix.org/conference/usenixsecurity20/presentation/osterlund)

<details>
  <summary>Click to see the abstract!</summary>
One of the key questions when fuzzing is where to look for vulnerabilities. Coverage-guided fuzzers indiscriminately optimize for covering as much code as possible given that bug coverage often correlates with code coverage. Since code coverage overapproximates bug coverage, this approach is less than ideal and may lead to non-trivial timeto-exposure (TTE) of bugs. Directed fuzzers try to address this problem by directing the fuzzer to a basic block with a potential vulnerability. This approach can greatly reduce the TTE for a specific bug, but such special-purpose fuzzers can then greatly underapproximate overall bug coverage.

In this paper, we present sanitizer-guided fuzzing, a new design point in this space that specifically optimizes for bug coverage. For this purpose, we make the key observation that while the instrumentation performed by existing software sanitizers are regularly used for detecting fuzzer-induced error conditions, they can further serve as a generic and effective mechanism to identify interesting basic blocks for guiding fuzzers. We present the design and implementation of
ParmeSan, a new sanitizer-guided fuzzer that builds on this observation. We show that ParmeSan greatly reduces the TTE of real-world bugs, and finds bugs 37% faster than existing state-of-the-art coverage-based fuzzers (Angora) and 288% faster than directed fuzzers (AFLGo), while still covering the same set of bugs.
</details>

#### [RAID'20] Binary-level Directed Fuzzing for Use-After-Free Vulnerabilities 

[[paper]](https://arxiv.org/pdf/2002.10751.pdf) [[project]](https://github.com/strongcourage/uafuzz)

<details>
  <summary>Click to see the abstract!</summary>
Directed fuzzing focuses on automatically testing specific parts of the code by taking advantage of additional information such as (partial) bug stack trace, patches or risky operations. Key applications include bug reproduction, patch testing and static analysis report verification. Although directed fuzzing has received a lot of attention recently, hard-to-detect vulnerabilities such as Use-After-Free (UAF) are still not well addressed, especially at the binary level. We propose UAFuzz, the first (binary-level) directed greybox fuzzer dedicated to UAF bugs. The technique features a fuzzing engine tailored to UAF specifics, a lightweight code instrumentation and an efficient bug triage step. Experimental evaluation for bug reproduction on real cases demonstrates that UAFuzz
significantly outperforms state-of-the-art directed fuzzers in terms of fault detection rate, time to exposure and bug triaging. UAFUZZ has also been proven effective in patch testing, leading to the discovery of 30 new bugs (7 CVEs) in programs such as Perl, GPAC and GNU Patch. Finally, we provide to
the community a large fuzzing benchmark dedicated to UAF, built on both real codes and real bugs.
</details>

#### [arxiv'20] TOFU: Target-Oriented FUzzer 

[[paper]](https://arxiv.org/pdf/2004.14375.pdf)

<details>
  <summary>Click to see the abstract!</summary>
Program fuzzing—providing randomly constructed inputs to a computer program—has proved to be a powerful way to uncover bugs, find security vulnerabilities, and generate test inputs that increase code coverage. In many applications, however, one is interested in a target-oriented approach—one wants to find an input that causes the program to reach a specific target point in the program. We have created TOFU (for Target-Oriented FUzzer) to address the directed fuzzing problem. TOFU’s search is biased according to a distance metric that scores each input according to how close the input’s execution trace gets to the target locations. TOFU is also input-structure aware (i.e., the search makes use of a specification of a superset of the program’s allowed inputs). Our experiments on xmllint show that TOFU is 28% faster than AFLGo, while reaching 45% more targets. Moreover, both distanceguided search and exploitation of knowledge of the input structure
contribute significantly to TOFU’s performance.
</details>

#### [arxiv'20] SoK: The Progress, Challenges, and Perspectives of Directed Greybox Fuzzing 

[[paper]](https://arxiv.org/pdf/2005.11907.pdf)

<details>
  <summary>Click to see the abstract!</summary>
Greybox fuzzing has been the most scalable an practical approach to software testing. Most greybox fuzzing tools are coverage guided as code coverage is strongly correlated with bug coverage. However, since most covered codes may not contain bugs, blindly extending code coverage is less efficient, especially for corner cases. Unlike coverage-based fuzzers who extend the code coverage in an undirected manner, a directed fuzzer spends most of its time budget on reaching specific target locations (e.g., the bug-prone zone) without wasting resources stressing unrelated parts. Thus, directed greybox fuzzing is particularly suitable for
scenarios such as patch testing, bug reproduction, and special bug hunting. In this paper, we conduct the first in-depth study of directed greybox fuzzing. We investigate 28 state-of-the-art fuzzers (82% are published after 2019) closely related to DGF, which have various directed types and optimization techniques.
Based on the feature of DGF, we extract 15 metrics to conduct a thorough assessment of the collected tools and systemize the knowledge of this field. Finally, we summarize the challenges and provide perspectives of this field, aiming to facilitate and boost future research on this topic
</details>

#### [PRDC'20] GTFuzz: Guard Token Directed Grey-Box Fuzzing 

[[paper]](https://ieeexplore.ieee.org/document/9320425)

<details>
  <summary>Click to see the abstract!</summary>
Directed grey-box fuzzing is an effective technique to find bugs in programs with the guidance of user-specified target locations. However, it can hardly reach a target location guarded by certain syntax tokens (Guard Tokens for short), which is often seen in programs with string operations or grammar/lexical parsing. Only the test inputs containing Guard Tokens are likely to reach the target locations, which challenges the effectiveness of mutation-based fuzzers. In this paper, a Guard Token directed grey-box fuzzer called GTFuzz is presented, which extracts Guard Tokens according to the target locations first and then exploits them to direct the fuzzing. Specifically, to ensure the new test cases generated from mutations contain Guard Tokens, new strategies of seed prioritization, dictionary generation, and seed mutation are also proposed, so as to make them likely to reach the target locations. Experiments on real-world software show that GTFuzz can reach the target locations, reproduce crashes, and expose bugs more efficiently than the state-of-the-art grey-box fuzzers (i.e., AFL, AFLGO and FairFuzz). Moreover, GTFuzz identified 23 previously undiscovered bugs in LibXML2 and MJS.
</details>

#### [arxiv'20] DeFuzz: Deep Learning Guided Directed Fuzzing

[[paper]](https://arxiv.org/pdf/2010.12149.pdf)

<details>
  <summary>Click to see the abstract!</summary>
Fuzzing is one of the most effective technique to identify potential software vulnerabilities. Most of the fuzzers aim to improve the code coverage, and there is lack of directedness (e.g., fuzz the specified path in a software). In this paper, we proposed a deep learning (DL) guided directed fuzzing for software vulnerability detection, named DeFuzz. DeFuzz includes two main schemes: (1) we employ a pre-trained DL prediction model to identify the potentially vulnerable functions and the locations (i.e., vulnerable addresses). Precisely, we employ Bidirectional-LSTM (BiLSTM) to identify attention words, and the vulnerabilities are associated with these attention words in functions. (2) then we employ directly fuzzing to fuzz the potential vulnerabilities by generating inputs that tend to arrive the predicted locations. To evaluate the effectiveness and practical of the proposed DeFuzz technique, we have conducted experiments on real-world data sets. Experimental results show that our DeFuzz can discover coverage more and faster than AFL. Moreover, DeFuzz exposes 43 more bugs than AFL on real-world applications.Fuzzing is one of the most effective technique to identify potential software vulnerabilities. Most of the fuzzers aim to improve the code coverage, and there is lack of directedness (e.g., fuzz the specified path in a software). In this paper, we proposed a deep learning (DL) guided directed fuzzing for software vulnerability detection, named DeFuzz. DeFuzz includes two main schemes: (1) we employ a pre-trained DL prediction model to identify the potentially vulnerable functions and the locations (i.e., vulnerable addresses). Precisely, we employ Bidirectional-LSTM (BiLSTM) to identify attention words, and the vulnerabilities are associated with these attention words in functions. (2) then we employ directly fuzzing to fuzz the potential vulnerabilities by generating inputs that tend to arrive the predicted locations. To evaluate the effectiveness and practical of the proposed DeFuzz technique, we have conducted experiments on real-world data sets. Experimental results show that our DeFuzz can discover coverage more and faster than AFL. Moreover, DeFuzz exposes 43 more bugs than AFL on real-world applications.
</details>

#### [Appl.Sci.'21] Constructing More Complete Control Flow Graphs Utilizing Directed Gray-Box Fuzzing 

[[paper]](http://scholar.google.com/scholar_url?url=https://www.mdpi.com/2076-3417/11/3/1351/pdf&hl=en&sa=X&d=711092365885842228&ei=xtEhYLeDEomImQGchIPoBg&scisig=AAGBfm0RiHu5HK9O-eFeXC2IQVAB_j7uuQ&nossl=1&oi=scholaralrt&hist=PwFTpwMAAAAJ:9999838452572663757:AAGBfm1XQkPGAWqsnVNmnoCjOFuDv3QJWQ&html=)

<details>
  <summary>Click to see the abstract!</summary>
Control Flow Graphs (CFGs) provide fundamental data for many program analyses, such as malware analysis, vulnerability detection, code similarity analysis, etc. Existing techniques for constructing control flow graphs include static, dynamic, and hybrid analysis, which each having their own advantages and disadvantages. However, due to the difficulty of resolving indirect jump relations, the existing techniques are limited in completeness. In this paper, we propose a practical
technique that applies static analysis and dynamic analysis to construct more complete control flow graphs. The main innovation of our approach is to adopt directed gray-box fuzzing (DGF) instead of coverage-based gray-box fuzzing (CGF) used in the existing approach to generate test cases that can exercise indirect jumps. We first employ a static analysis to construct the static CFGs without indirect jump relations. Then, we utilize directed gray-box fuzzing to generate test cases and resolve indirect jump relations by monitoring the execution traces of these test cases. Finally, we combine the static CFGs with indirect jump relations to construct more complete CFGs. In addition, we also propose an iterative feedback mechanism to further improve the completeness of CFGs. We have implemented
our technique in a prototype and evaluated it through comparing with the existing approaches on eight benchmarks. The results show that our prototype can resolve more indirect jump relations and construct more complete CFGs than existing approaches.
</details>

#### [CCS'21] Regression Greybox Fuzzing

[[paper]](https://mboehme.github.io/paper/CCS21.pdf) [[project]](https://github.com/aflchurn/aflchurn) [[dataset]](https://www.kaggle.com/marcelbhme/aflchurn-ccs21/code)  

<details>
  <summary>Click to see the abstract!</summary>
What you change is what you fuzz! In an empirical study of all fuzzer-generated bug reports in OSSFuzz, we found that four in every five bugs have been introduced by recent code changes. That is, 77% of 23k bugs are regressions. For a newly added project, there is usually an initial burst of new reports at 2-3 bugs per day. However, after that initial burst, and after weeding out most of the existing bugs, we still get a constant rate of 3-4 bug reports per week. The constant rate can only be explained by an increasing regression rate. Indeed, the probability that a reported bug is a regression (i.e., we could identify the bug-introducing commit) increases from 20% for the first bug to 92% after a few hundred bug reports.
In this paper, we introduce regression greybox fuzzing (RGF) a fuzzing approach that focuses on code that has changed more recently or more often. However, for any active software project, it is impractical to fuzz sufficiently each code commit individually. Instead, we propose to fuzz all commits simultaneously, but code present in more (recent) commits with higher priority. We observe that most code is never changed and relatively old. So, we identify means to strengthen the signal from executed code-of-interest. We also extend the concept of power schedules to the bytes of a seed and introduce Ant Colony Optimization to assign more energy to those bytes which promise to generate more interesting inputs.
Our large-scale fuzzing experiment demonstrates the validity of our main hypothesis and the efficiency of regression greybox fuzzing. We conducted our experiments in a reproducible manner within Fuzzbench, an extensible fuzzer evaluation platform. Our experiments involved 3+ CPU-years worth of fuzzing campaigns and 20 bugs in 15 open-source C programs available on OSSFuzz.
</details>
