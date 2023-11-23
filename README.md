# awesome-directed-fuzzing

Directed Fuzzing seems to be a current hot research topic. This repository aims to provide a curated list of research papers focusing on directed greybox fuzzing (see more [directed whitebox fuzzing](./whitebox.md) and [miscellaneous](./misc.md)).

--------------------------------------------------------------------------------------------------------------------------
### [CCS'17] Directed Greybox Fuzzing 

[[paper]](https://mboehme.github.io/paper/CCS17.pdf) [[project]](https://github.com/aflgo) [[slides]](https://www.slideshare.net/mboehme/aflgo-directed-greybox-fuzzing) [[talk]](https://www.youtube.com/watch?v=jiECNix0HuQ)

<details>
  <summary>Click to see the abstract!</summary>
Existing Greybox Fuzzers (GF) cannot be effectively directed, for instance, towards problematic changes or patches, towards critical system calls or dangerous locations, or towards functions in the stacktrace of a reported vulnerability that we wish to reproduce. In this paper, we introduce Directed Greybox Fuzzing (DGF) which generates inputs with the objective of reaching a given set of target program locations efficiently. We develop and evaluate a simulated annealing-based power schedule that gradually assigns more energy to seeds that are closer to the target locations while reducing energy for seeds that are further away. Experiments with our implementation AFLGo demonstrate that DGF outperforms both directed symbolic-execution-based whitebox fuzzing and undirected greybox fuzzing. We show applications of DGF to patch testing and crash reproduction, and discuss the integration of AFLGo into Google’s continuous fuzzing platform OSS-Fuzz. Due
to its directedness, AFLGo could find 39 bugs in several well-fuzzed, security-critical projects like LibXML2. 17 CVEs were assigned.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [CCS'18] Hawkeye: Towards a Desired Directed Grey-box Fuzzer 

[[paper]](https://hongxuchen.github.io/pdf/hawkeye.pdf) [[project]](https://sites.google.com/view/fot-the-fuzzer/DGF?authuser=0) [[slides]](https://hongxuchen.github.io/pdf/hawkeye-slides.pdf) [[talk]](https://www.youtube.com/watch?v=BSPj7GAQt5U&list=PLn0nrSd4xjjbyUeai0oevMrT8_IwnBo4R&index=7)

<details>
  <summary>Click to see the abstract!</summary>
Grey-box fuzzing is a practically effective approach to test realworld programs. However, most existing grey-box fuzzers lack directedness, i.e. the capability of executing towards user-specified target sites in the program. To emphasize existing challenges in directed fuzzing, we propose Hawkeye to feature four desired properties of directed grey-box fuzzers. Owing to a novel static analysis on the program under test and the target sites, Hawkeye precisely collects the information such as the call graph, function and basic block level distances to the targets. During fuzzing, Hawkeye evaluates exercised seeds based on both static information and the execution traces to generate the dynamic metrics, which are then used for seed prioritization, power scheduling and adaptive mutating.
These strategies help Hawkeye to achieve better directedness and gravitate towards the target sites. We implemented Hawkeye as a fuzzing framework and evaluated it on various real-world programs under different scenarios. The experimental results showed that Hawkeye can reach the target sites and reproduce the crashes much faster than state-of-the-art grey-box fuzzers such as AFL and AFLGo. Specially, Hawkeye can reduce the time to exposure for certain vulnerabilities from about 3.5 hours to 0.5 hour. By now, Hawkeye has detected more than 41 previously unknown crashes in projects such as Oniguruma, MJS with the target sites provided by vulnerability prediction tools; all these crashes are confirmed and 15 of them have been assigned CVE IDs.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [DSN'19] 1dVul: Discovering 1-day Vulnerabilities through Binary Patches 

[[paper]](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=8809537)

<details>
  <summary>Click to see the abstract!</summary>
Discovering 1-day vulnerabilities in binary patches is worthwhile but challenging. One of the key difficulties lies in generating inputs that could reach the patched code snippet while making the unpatched program crash. In this paper, we named it as a target-oriented input generation problem or a ToIG problem for clarity. Existing solutions for the ToIG problem either suffer from path explosion or may get stuck by complex checks. In the paper, we present a new solution to improve the efficiency of ToIG which leverage a combination of a distance-based directed fuzzing mechanism and a dominator-based directed symbolic execution mechanism. To demonstrate its efficiency, we design and implement 1dVul, a tool for 1-day vulnerability discovering at binary-level, based on the solution. Demonstrations show that 1dVul has successfully generated inputs for 130 targets from a total of 209 patch targets identified from applications in DARPA Cyber Grant Challenge, while the state-of-the-art solutions AFLGo and Driller can only reach 99 and 107 targets, respectively, within the same limited time budget. Further-more, 1dVul runs 2.2X and 3.6X faster than AFLGo and Driller, respectively, and has confirmed 96 vulnerabilities from the unpatched programs.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [ICPC'19] Sequence coverage directed greybox fuzzing 

[[paper]](https://dl.acm.org/doi/10.1109/ICPC.2019.00044)

<details>
  <summary>Click to see the abstract!</summary>
Existing directed fuzzers are not efficient enough. Directed symbolic-execution-based whitebox fuzzers, e.g. BugRedux, spend lots of time on heavyweight program analysis and constraints solving at runtime. Directed greybox fuzzers, such as AFLGo, perform well at runtime, but considerable calculation during instrumentation phase hinders the overall performance.

In this paper, we propose Sequence-coverage Directed Fuzzing (SCDF), a lightweight directed fuzzing technique which explores towards the user-specified program statements efficiently. Given a set of target statement sequences of a program, SCDF aims to generate inputs that can reach the statements in each sequence in order and trigger bugs in the program. Moreover, we present a novel energy schedule algorithm, which adjusts on demand a seed's energy according to its ability of covering the given statement sequences calculated on demand. We implement the technique in a tool LOLLY in order to achieve efficiency both at instrumentation time and at runtime. Experiments on several real-world software projects demonstrate that LOLLY outperforms two well-established tools on efficiency and effectiveness, i.e., AFLGo-a directed greybox fuzzer and BugRedux-a directed symbolic-execution-based whitebox fuzzer.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [CCS'19] Poster: Directed Hybrid Fuzzing on Binary Code 

[[paper]](https://dl.acm.org/doi/abs/10.1145/3319535.3363275)

<details>
  <summary>Click to see the abstract!</summary>
Hybrid fuzzers combine both fuzzing and concolic execution with the wish that the fuzzer will quickly explore input spaces and the concolic execution will solve the complex path conditions. However, existing hybrid fuzzers such as Driller cannot be effectively directed, for instance, towards unsafe system calls or suspicious locations, or towards functions in the call stack of a reported vulnerability that we wish to reproduce. In this poster, we propose DrillerGO, a directed hybrid fuzzing system, to mitigate this problem. It mainly consists of a static analysis and a dynamic analysis module. In the static analysis, it searches suspicious API call strings in the recovered control flow graph (CFG). After targeting some suspicious API call lines, it runs the concolic execution along with path guiding. The path guiding is helped by backward pathfinding, which is a novel technique to find paths backward from the target to the start of main(). Also, we will show that DrillerGo can find the crashes faster than Driller through experimental results.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [ICSE'19] LEOPARD: Identifying Vulnerable Code for Vulnerability Assessment through Program Metrics 

[[paper]](https://arxiv.org/pdf/1901.11479.pdf) [[project]](https://sites.google.com/site/leopardsite2017/)

<details>
  <summary>Click to see the abstract!</summary>
Identifying potentially vulnerable locations in a code base is critical as a pre-step for effective vulnerability assessment; i.e., it can greatly help security experts put their time and effort to where it is needed most. Metric-based and pattern-based methods have been presented for identifying vulnerable code. The former relies on machine learning and cannot work well due to the severe imbalance between non-vulnerable and vulnerable code or lack of features to characterize vulnerabilities. The latter needs the prior knowledge of known vulnerabilities and can only identify similar but not new types of vulnerabilities.

In this paper, we propose and implement a generic, lightweight and extensible framework, LEOPARD, to identify potentially vulnerable functions through program metrics. LEOPARD requires no prior knowledge about known vulnerabilities. It has two steps by combining two sets of systematically derived metrics. First, it
uses complexity metrics to group the functions in a target application into a set of bins. Then, it uses vulnerability metrics to rank the functions in each bin and identifies the top ones as potentially vulnerable. Our experimental results on 11 real-world projects have demonstrated that, LEOPARD can cover 74.0% of vulnerable functions by identifying 20% of functions as vulnerable and outperform machine learning-based and static analysis-based techniques. We further propose three applications of LEOPARD for manual code review and fuzzing, through which we discovered 22 new bugs in real applications like PHP, radare2 and FFmpeg, and eight of them are new vulnerabilities.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [arxiv'19] V-Fuzz: Vulnerability-Oriented Evolutionary Fuzzing 

[[paper]](https://arxiv.org/pdf/1901.01142.pdf)

<details>
  <summary>Click to see the abstract!</summary>
Fuzzing is a technique of finding bugs by executing a software recurrently with a large number of abnormal inputs. Most of the existing fuzzers consider all parts of a software equally, and pay too much attention on how to improve the code coverage. It is inefficient as the vulnerable code only takes a tiny fraction of the entire code. In this paper, we design and implement a vulnerability-oriented evolutionary fuzzing prototype named V-Fuzz, which aims to find bugs efficiently and quickly in a limited time. V-Fuzz consists of two main components: a neural network-based vulnerability prediction model and a vulnerability-oriented evolutionary fuzzer. Given a binary program to V-Fuzz, the vulnerability prediction model will give a prior estimation on which parts of the software are more likely to be vulnerable. Then, the fuzzer leverages an evolutionary algorithm to generate inputs which tend to arrive at the vulnerable locations, guided by the vulnerability prediction result. Experimental results demonstrate that V-Fuzz can find bugs more efficiently than state-of-the-art fuzzers. Moreover, V-Fuzz has discovered 10 CVEs, and 3 of them are newly discovered. We reported the new CVEs, and they have been confirmed and fixed.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [SANER'20] Sequence directed hybrid fuzzing 

[[paper]](./sequence_hybrid.pdf)

<details>
  <summary>Click to see the abstract!</summary>
Existing directed grey-box fuzzers are effective compared with coverage-based fuzzers. However, they fail to achieve a balance between effectiveness and efficiency, and it is difficult to cover complex paths due to random mutation. To mitigate the issue, we propose a novel approach, sequence directed hybrid fuzzing (SDHF), which leverages a sequence-directed strategy and concolic execution technique to enhance the effectiveness of fuzzing. Given a set of target statement sequences of a program, SDHF aims to generate inputs that can reach the statements in each sequence in order and trigger potential bugs in the program. We implement the proposed approach in a tool called Berry and evaluate its capability on crash reproduction, true positive verification, and vulnerability detection. Experimental results demonstrate that Berry outperforms four state-of-the-art fuzzers, including directed fuzzers BugRedux, AFLGo and Lolly, and undirected hybrid fuzzer QSYM. Moreover, Berry found 7 new vulnerabilities in real-world programs such as UPX and GNU Libextractor, and 3 new CVEs were assigned.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [ICSE'20] Targeted Greybox Fuzzing with Static Lookahead Analysis 

[[paper]](https://mariachris.github.io/Pubs/ICSE-2020.pdf) [[talk]](https://www.youtube.com/watch?v=86vvChVr9bQ)

<details>
  <summary>Click to see the abstract!</summary>
Automatic test generation typically aims to generate inputs that explore new paths in the program under test in order to find bugs. Existing work has, therefore, focused on guiding the exploration toward program parts that are more likely to contain bugs by using an offline static analysis. In this paper, we introduce a novel technique for targeted greybox fuzzing using an online static analysis that guides the fuzzer toward a set of target locations, for instance, located in recently modified parts of the program. This is achieved by first semantically analyzing each program path that is explored by an input in the fuzzer’s test suite. The results of this analysis are then used to control the fuzzer’s specialized power schedule, which determines how often to fuzz inputs from the test suite. We implemented our technique by extending a state-of-the-art, industrial fuzzer for Ethereum smart contracts and evaluate its effectiveness on 27 real-world benchmarks. Using an online analysis is particularly suitable for the domain of smart contracts since it does not require any code instrumentation-adding instrumentation to contracts changes their semantics. Our experiments show that targeted fuzzing significantly outperforms standard greybox fuzzing for reaching 83% of the challenging target locations (up to 14x of median speed-up).
</details>

--------------------------------------------------------------------------------------------------------------------------
### [SEC'20] FuzzGuard: Filtering out Unreachable Inputs in Directed Grey-box Fuzzing through Deep Learning 

[[paper]](http://kaichen.org/paper/conference/sec20summer-final343.pdf) [[project]](https://github.com/zongpy/FuzzGuard) [[slides]](https://www.usenix.org/system/files/sec20_slides_zong.pdf) [[talk]](https://www.usenix.org/conference/usenixsecurity20/presentation/zong)

<details>
  <summary>Click to see the abstract!</summary>
Recently, directed grey-box fuzzing (DGF) becomes popular in the field of software testing. Different from coverage-based fuzzing whose goal is to increase code coverage for triggering more bugs, DGF is designed to check whether a piece of potentially buggy code (e.g., string operations) really contains a bug. Ideally, all the inputs generated by DGF should reach the target buggy code until triggering the bug. It is a waste of time when executing with unreachable inputs. Unfortunately, in real situations, large numbers of the generated inputs cannot let a program execute to the target, greatly impacting the efficiency of fuzzing, especially when the buggy code is embedded in the code guarded by various constraints. 
  
In this paper, we propose a deep-learning-based approach to predict the reachability of inputs (i.e., miss the target or not) before executing the target program, helping DGF filtering out the unreachable ones to boost the performance of fuzzing. To apply deep learning with DGF, we design a suite of new techniques (e.g., step-forwarding approach, representative data selection) to solve the problems of unbalanced labeled data and insufficient time in the training process. Further, we implement the proposed approach called FuzzGuard and equip it
with the state-of-the-art DGF (e.g., AFLGo). Evaluations on 45 real vulnerabilities show that FuzzGuard boosts the fuzzing efficiency of the vanilla AFLGo up to 17.1×. Finally, to understand the key features learned by FuzzGuard, we illustrate their connection with the constraints in the programs
</details>

--------------------------------------------------------------------------------------------------------------------------
### [SEC'20] ParmeSan: Sanitizer-guided Greybox Fuzzing 

[[paper]](https://download.vusec.net/papers/parmesan_sec20.pdf) [[project]](https://github.com/vusec/parmesan) [[slides]](https://www.usenix.org/system/files/sec20_slides_osterlund.pdf) [[talk]](https://www.usenix.org/conference/usenixsecurity20/presentation/osterlund)

<details>
  <summary>Click to see the abstract!</summary>
One of the key questions when fuzzing is where to look for vulnerabilities. Coverage-guided fuzzers indiscriminately optimize for covering as much code as possible given that bug coverage often correlates with code coverage. Since code coverage overapproximates bug coverage, this approach is less than ideal and may lead to non-trivial timeto-exposure (TTE) of bugs. Directed fuzzers try to address this problem by directing the fuzzer to a basic block with a potential vulnerability. This approach can greatly reduce the TTE for a specific bug, but such special-purpose fuzzers can then greatly underapproximate overall bug coverage.

In this paper, we present sanitizer-guided fuzzing, a new design point in this space that specifically optimizes for bug coverage. For this purpose, we make the key observation that while the instrumentation performed by existing software sanitizers are regularly used for detecting fuzzer-induced error conditions, they can further serve as a generic and effective mechanism to identify interesting basic blocks for guiding fuzzers. We present the design and implementation of
ParmeSan, a new sanitizer-guided fuzzer that builds on this observation. We show that ParmeSan greatly reduces the TTE of real-world bugs, and finds bugs 37% faster than existing state-of-the-art coverage-based fuzzers (Angora) and 288% faster than directed fuzzers (AFLGo), while still covering the same set of bugs.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [RAID'20] Binary-level Directed Fuzzing for Use-After-Free Vulnerabilities 

[[paper]](https://arxiv.org/pdf/2002.10751.pdf) [[project]](https://github.com/strongcourage/uafuzz)

<details>
  <summary>Click to see the abstract!</summary>
Directed fuzzing focuses on automatically testing specific parts of the code by taking advantage of additional information such as (partial) bug stack trace, patches or risky operations. Key applications include bug reproduction, patch testing and static analysis report verification. Although directed fuzzing has received a lot of attention recently, hard-to-detect vulnerabilities such as Use-After-Free (UAF) are still not well addressed, especially at the binary level. We propose UAFuzz, the first (binary-level) directed greybox fuzzer dedicated to UAF bugs. The technique features a fuzzing engine tailored to UAF specifics, a lightweight code instrumentation and an efficient bug triage step. Experimental evaluation for bug reproduction on real cases demonstrates that UAFuzz
significantly outperforms state-of-the-art directed fuzzers in terms of fault detection rate, time to exposure and bug triaging. UAFUZZ has also been proven effective in patch testing, leading to the discovery of 30 new bugs (7 CVEs) in programs such as Perl, GPAC and GNU Patch. Finally, we provide to
the community a large fuzzing benchmark dedicated to UAF, built on both real codes and real bugs.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [arxiv'20] TOFU: Target-Oriented FUzzer 

[[paper]](https://arxiv.org/pdf/2004.14375.pdf)

<details>
  <summary>Click to see the abstract!</summary>
Program fuzzing—providing randomly constructed inputs to a computer program—has proved to be a powerful way to uncover bugs, find security vulnerabilities, and generate test inputs that increase code coverage. In many applications, however, one is interested in a target-oriented approach—one wants to find an input that causes the program to reach a specific target point in the program. We have created TOFU (for Target-Oriented FUzzer) to address the directed fuzzing problem. TOFU’s search is biased according to a distance metric that scores each input according to how close the input’s execution trace gets to the target locations. TOFU is also input-structure aware (i.e., the search makes use of a specification of a superset of the program’s allowed inputs). Our experiments on xmllint show that TOFU is 28% faster than AFLGo, while reaching 45% more targets. Moreover, both distanceguided search and exploitation of knowledge of the input structure
contribute significantly to TOFU’s performance.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [arxiv'20] SoK: The Progress, Challenges, and Perspectives of Directed Greybox Fuzzing 

[[paper]](https://arxiv.org/pdf/2005.11907.pdf)

<details>
  <summary>Click to see the abstract!</summary>
Greybox fuzzing has been the most scalable an practical approach to software testing. Most greybox fuzzing tools are coverage guided as code coverage is strongly correlated with bug coverage. However, since most covered codes may not contain bugs, blindly extending code coverage is less efficient, especially for corner cases. Unlike coverage-based fuzzers who extend the code coverage in an undirected manner, a directed fuzzer spends most of its time budget on reaching specific target locations (e.g., the bug-prone zone) without wasting resources stressing unrelated parts. Thus, directed greybox fuzzing is particularly suitable for
scenarios such as patch testing, bug reproduction, and special bug hunting. In this paper, we conduct the first in-depth study of directed greybox fuzzing. We investigate 28 state-of-the-art fuzzers (82% are published after 2019) closely related to DGF, which have various directed types and optimization techniques.
Based on the feature of DGF, we extract 15 metrics to conduct a thorough assessment of the collected tools and systemize the knowledge of this field. Finally, we summarize the challenges and provide perspectives of this field, aiming to facilitate and boost future research on this topic
</details>

--------------------------------------------------------------------------------------------------------------------------
### [PRDC'20] GTFuzz: Guard Token Directed Grey-Box Fuzzing 

[[paper]](https://ieeexplore.ieee.org/document/9320425)

<details>
  <summary>Click to see the abstract!</summary>
Directed grey-box fuzzing is an effective technique to find bugs in programs with the guidance of user-specified target locations. However, it can hardly reach a target location guarded by certain syntax tokens (Guard Tokens for short), which is often seen in programs with string operations or grammar/lexical parsing. Only the test inputs containing Guard Tokens are likely to reach the target locations, which challenges the effectiveness of mutation-based fuzzers. In this paper, a Guard Token directed grey-box fuzzer called GTFuzz is presented, which extracts Guard Tokens according to the target locations first and then exploits them to direct the fuzzing. Specifically, to ensure the new test cases generated from mutations contain Guard Tokens, new strategies of seed prioritization, dictionary generation, and seed mutation are also proposed, so as to make them likely to reach the target locations. Experiments on real-world software show that GTFuzz can reach the target locations, reproduce crashes, and expose bugs more efficiently than the state-of-the-art grey-box fuzzers (i.e., AFL, AFLGO and FairFuzz). Moreover, GTFuzz identified 23 previously undiscovered bugs in LibXML2 and MJS.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [arxiv'20] DeFuzz: Deep Learning Guided Directed Fuzzing

[[paper]](https://arxiv.org/pdf/2010.12149.pdf)

<details>
  <summary>Click to see the abstract!</summary>
Fuzzing is one of the most effective technique to identify potential software vulnerabilities. Most of the fuzzers aim to improve the code coverage, and there is lack of directedness (e.g., fuzz the specified path in a software). In this paper, we proposed a deep learning (DL) guided directed fuzzing for software vulnerability detection, named DeFuzz. DeFuzz includes two main schemes: (1) we employ a pre-trained DL prediction model to identify the potentially vulnerable functions and the locations (i.e., vulnerable addresses). Precisely, we employ Bidirectional-LSTM (BiLSTM) to identify attention words, and the vulnerabilities are associated with these attention words in functions. (2) then we employ directly fuzzing to fuzz the potential vulnerabilities by generating inputs that tend to arrive the predicted locations. To evaluate the effectiveness and practical of the proposed DeFuzz technique, we have conducted experiments on real-world data sets. Experimental results show that our DeFuzz can discover coverage more and faster than AFL. Moreover, DeFuzz exposes 43 more bugs than AFL on real-world applications.Fuzzing is one of the most effective technique to identify potential software vulnerabilities. Most of the fuzzers aim to improve the code coverage, and there is lack of directedness (e.g., fuzz the specified path in a software). In this paper, we proposed a deep learning (DL) guided directed fuzzing for software vulnerability detection, named DeFuzz. DeFuzz includes two main schemes: (1) we employ a pre-trained DL prediction model to identify the potentially vulnerable functions and the locations (i.e., vulnerable addresses). Precisely, we employ Bidirectional-LSTM (BiLSTM) to identify attention words, and the vulnerabilities are associated with these attention words in functions. (2) then we employ directly fuzzing to fuzz the potential vulnerabilities by generating inputs that tend to arrive the predicted locations. To evaluate the effectiveness and practical of the proposed DeFuzz technique, we have conducted experiments on real-world data sets. Experimental results show that our DeFuzz can discover coverage more and faster than AFL. Moreover, DeFuzz exposes 43 more bugs than AFL on real-world applications.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [Appl.Sci.'21] Constructing More Complete Control Flow Graphs Utilizing Directed Gray-Box Fuzzing 

[[paper]](http://scholar.google.com/scholar_url?url=https://www.mdpi.com/2076-3417/11/3/1351/pdf&hl=en&sa=X&d=711092365885842228&ei=xtEhYLeDEomImQGchIPoBg&scisig=AAGBfm0RiHu5HK9O-eFeXC2IQVAB_j7uuQ&nossl=1&oi=scholaralrt&hist=PwFTpwMAAAAJ:9999838452572663757:AAGBfm1XQkPGAWqsnVNmnoCjOFuDv3QJWQ&html=)

<details>
  <summary>Click to see the abstract!</summary>
Control Flow Graphs (CFGs) provide fundamental data for many program analyses, such as malware analysis, vulnerability detection, code similarity analysis, etc. Existing techniques for constructing control flow graphs include static, dynamic, and hybrid analysis, which each having their own advantages and disadvantages. However, due to the difficulty of resolving indirect jump relations, the existing techniques are limited in completeness. In this paper, we propose a practical
technique that applies static analysis and dynamic analysis to construct more complete control flow graphs. The main innovation of our approach is to adopt directed gray-box fuzzing (DGF) instead of coverage-based gray-box fuzzing (CGF) used in the existing approach to generate test cases that can exercise indirect jumps. We first employ a static analysis to construct the static CFGs without indirect jump relations. Then, we utilize directed gray-box fuzzing to generate test cases and resolve indirect jump relations by monitoring the execution traces of these test cases. Finally, we combine the static CFGs with indirect jump relations to construct more complete CFGs. In addition, we also propose an iterative feedback mechanism to further improve the completeness of CFGs. We have implemented
our technique in a prototype and evaluated it through comparing with the existing approaches on eight benchmarks. The results show that our prototype can resolve more indirect jump relations and construct more complete CFGs than existing approaches.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [DAC'21] DirectFuzz: Automated Test Generation for RTL Designs using Directed Graybox Fuzzing

[[paper]](https://ieeexplore.ieee.org/document/9586289)

<details>
  <summary>Click to see the abstract!</summary>
A critical challenge in RTL verification is to generate effective test inputs. Recently, RFUZZ proposed to use an automated software testing technique, namely Graybox Fuzzing, to effectively generate test inputs to maximize the coverage of the whole hardware design. For a scenario where a tiny fraction of a large hardware design needs to be tested, the RFUZZ approach is extremely time consuming. In this work, we present DirectFuzz, a directed test generation mechanism. DirectFuzz uses Directed Graybox Fuzzing to generate test inputs targeted towards a module instance, which enables targeted testing. Our experimental results show that DirectFuzz covers the target sites up to 17.5× faster (2.23× on average) than RFUZZ on a variety of RTL designs.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [CCS'21] Regression Greybox Fuzzing

[[paper]](https://mboehme.github.io/paper/CCS21.pdf) [[project]](https://github.com/aflchurn/aflchurn) [[dataset]](https://www.kaggle.com/marcelbhme/aflchurn-ccs21/code)  

<details>
  <summary>Click to see the abstract!</summary>
What you change is what you fuzz! In an empirical study of all fuzzer-generated bug reports in OSSFuzz, we found that four in every five bugs have been introduced by recent code changes. That is, 77% of 23k bugs are regressions. For a newly added project, there is usually an initial burst of new reports at 2-3 bugs per day. However, after that initial burst, and after weeding out most of the existing bugs, we still get a constant rate of 3-4 bug reports per week. The constant rate can only be explained by an increasing regression rate. Indeed, the probability that a reported bug is a regression (i.e., we could identify the bug-introducing commit) increases from 20% for the first bug to 92% after a few hundred bug reports.
In this paper, we introduce regression greybox fuzzing (RGF) a fuzzing approach that focuses on code that has changed more recently or more often. However, for any active software project, it is impractical to fuzz sufficiently each code commit individually. Instead, we propose to fuzz all commits simultaneously, but code present in more (recent) commits with higher priority. We observe that most code is never changed and relatively old. So, we identify means to strengthen the signal from executed code-of-interest. We also extend the concept of power schedules to the bytes of a seed and introduce Ant Colony Optimization to assign more energy to those bytes which promise to generate more interesting inputs.
Our large-scale fuzzing experiment demonstrates the validity of our main hypothesis and the efficiency of regression greybox fuzzing. We conducted our experiments in a reproducible manner within Fuzzbench, an extensible fuzzer evaluation platform. Our experiments involved 3+ CPU-years worth of fuzzing campaigns and 20 bugs in 15 open-source C programs available on OSSFuzz.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [ICAIS'21] KCFuzz: Directed Fuzzing Based on Keypoint Coverage

[[paper]](https://link.springer.com/chapter/10.1007/978-3-030-78609-0_27)

<details>
  <summary>Click to see the abstract!</summary>
Directed fuzzing, as an efficient method to focus on a specific set of targets in the program, often works better than random fuzzing when combined with a researcher’s empirical judgment. However, the current directed fuzzing work is not efficient enough. In previous studies, some have generated closer seed inputs by guiding the execution path through the distance from the target region, but the distance guided algorithm is less robust. Some studies used selective symbolic execution for directed testing to alleviate the path explosion problem, but it brings a higher false-positive rate. In this paper, we propose a keypoint coverage-based fuzzing (KCFuzz) method, which extracts the keypoint list using a control flow graph, obtains the keypoint list coverage information through runtime instrumentation, calculates the test priority of the seeds based on the overall coverage and keypoint coverage using an energy scheduling algorithm, and continuously generates test inputs closer to the target according to the specified mutation strategy. On this basis, a hybrid testing framework is implemented, using keypoint coverage directed fuzzing to generate a seed queue covering keypoints, using offspring generation strategies and hybrid execution technology, and further exploring the new state of the program according to changes in overall and keypoint coverage. The experimental results show that the KCFuzz method can efficiently induce the generation of seed queues to reach the target region, and at the same time, the depth and validity of the exploration paths are higher than those of the most advanced directed fuzzing methods such as AFLGo.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [Usenix'21] Constraint-guided Directed Greybox Fuzzing

[[paper]](https://www.usenix.org/system/files/sec21fall-lee-gwangmu.pdf) [[slides]](https://www.usenix.org/system/files/sec21_slides_lee-gwangmu.pdf) [[talk]](https://www.youtube.com/watch?v=v3PUtjGC2_g)

<details>
  <summary>Click to see the abstract!</summary>
Directed greybox fuzzing is an augmented fuzzing technique intended for the targeted usages such as crash reproduction and proof-of-concept generation, which gives directedness to fuzzing by driving the seeds toward the designated program locations called target sites. However, we find that directed greybox fuzzing can still suffer from the long fuzzing time before exposing the targeted crash, because it does not consider the ordered target sites and the data conditions. This paper presents constraint-guided directed greybox fuzzing that aims to satisfy a sequence of constraints rather than merely reaching a set of target sites. Constraint-guided grey-box fuzzing defines a constraint as the combination of a target site and the data conditions, and drives the seeds to satisfy the constraints in the specified order. We automatically generate the constraints with seven types of crash dumps and four types of patch changelogs, and evaluate the prototype system CAFL against the representative directed greybox fuzzing system AFLGo with 47 real-world crashes and 12 patch changelogs. The evaluation shows CAFL outperforms AFLGo by 2.88x for crash reproduction, and better performs in PoC generation as the constraints get explicit.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [ASE'21 NIER] Towards Systematic and Dynamic Task Allocation for Collaborative Parallel Fuzzing

[[paper]](https://thuanpv.github.io/publications/AFLTeam-ASE21-NIER.pdf) [[project]](https://github.com/MelbourneFuzzingHub/aflteam)

<details>
  <summary>Click to see the abstract!</summary>
Parallel coverage-guided greybox fuzzing is the most common setup for vulnerability discovery at scale. However, so far it has received little attention from the research community compared to single-mode fuzzing, leaving open several problems particularly in its task allocation strategies. Current approaches focus on managing micro tasks, at the seed input level, and their task division algorithms are either ad-hoc or static. In this paper, we leverage research on graph partitioning and search algorithms to propose a systematic and dynamic task allocation solution that works at the macro-task level. First, we design an attributed graph to capture both the program structures (e.g., program call graph) and fuzzing information (e.g., branch hit counts, bug discovery probability). Second, our graph partitioning algorithm divides the global program search space into sub-search-spaces. Finally our search algorithm prioritizes these sub-search-spaces (i.e., tasks) and explores them to maximize code coverage and number of bugs found. We implemented a prototype tool called AFLTeam. In our preliminary experiments on well-tested benchmarks, AFLTeam achieved higher code coverage (up to 16.4% branch coverage improvement) compared to the default parallel mode of AFL and discovered 2 zero-day bugs in FFmpeg and JasPer toolkits.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [arxiv'21] Finding Counterexamples of Temporal Logic properties in Software Implementations via Greybox Fuzzing

[[paper]](https://arxiv.org/pdf/2109.02312.pdf)

<details>
  <summary>Click to see the abstract!</summary>
Software model checking is a verification technique which is widely used for checking temporal properties of software systems. Even though it is a property verification technique, its common usage in practice is in "bug finding", that is, finding violations of temporal properties. Motivated by this observation and leveraging the recent progress in fuzzing, we build a greybox fuzzing framework to find violations of Linear-time Temporal Logic (LTL) properties.
Our framework takes as input a sequential program written in C/C++, and an LTL property. It finds violations, or counterexample traces, of the LTL property in stateful software systems; however, it does not achieve verification. Our work substantially extends directed greybox fuzzing to witness arbitrarily complex event or-derings. We note that existing directed greybox fuzzing approaches are limited to witnessing reaching a location or witnessing simple event orderings like use-after-free. At the same time, compared to model checkers, our approach finds the counterexamples faster, thereby finding more counterexamples within a given time budget.
Our LTL-Fuzzer tool, built on top of the AFL fuzzer, is shown to be effective in detecting bugs in well-known protocol implementations, such as OpenSSL and Telnet. We use LTL-Fuzzer to reproduce known vulnerabilities (CVEs), to find 15 zero-day bugs by checking properties extracted from RFCs (for which 10 CVEs have been assigned), and to find violations of both safety as well as liveness properties in real-world protocol implementations. Our work represents a practical advance over software model checkers — while simultaneously representing a conceptual advance over existing greybox fuzzers. Our work thus provides a starting point for understanding the unexplored synergies between software model checking and greybox fuzzing.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [S&P'22] BEACON : Directed Grey-Box Fuzzing with Provable Path Pruning

[[paper]](https://qingkaishi.github.io/public_pdfs/SP22.pdf) [[project]](https://hub.docker.com/r/yguoaz/beacon)

<details>
  <summary>Click to see the abstract!</summary>
Unlike coverage-based fuzzing that gives equal attention to every part of a code, directed fuzzing aims to direct a fuzzer to a specific target in the code, e.g., the code with potential vulnerabilities. Despite much progress, we observe that existing directed fuzzers are still not efficient as they often symbolically or concretely execute a lot of program paths that cannot reach the target code. They thus waste a lot of computational resources. This paper presents BEACON, which can effectively direct a grey-box fuzzer in the sea of paths in a provable manner. That is, assisted by a lightweight static analysis that computes abstracted preconditions for reaching the target, we can prune 82.94% of the executing paths at runtime with negligible analysis overhead (<5h) but with the guarantee that the pruned paths must be spurious with respect to the target. We have implemented our approach, BEACON, and compared it to five state-of-the-art (directed) fuzzers in the application scenario of vulnerability reproduction. The evaluation results demonstrate that BEACON is 11.50x faster on average than existing directed grey-box fuzzers and it can also improve the speed of the conventional coverage-guided fuzzers, AFL, AFL++, and Mopt, to reproduce specific bugs with 6.31x ,11.86x, and 10.92x speedup, respectively. More interestingly, when used to test the vulnerability patches, BEACON found 14 incomplete fixes of existing CVE-identified vulnerabilities and 8 new bugs while 10 of them are exploitable with new CVE ids assigned.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [ICSE'22] WindRanger: A Directed Greybox Fuzzer driven by Deviation Basic Block

[[paper]](https://drive.google.com/file/d/1VTlFoOE5uUzL7_b5OwGWCEcMDlNC_SBF/view) [[project]](https://sites.google.com/view/windranger-directed-fuzzing/home?authuser=0) [[talk]](https://www.youtube.com/watch?v=MUmaI4evzc4)
  
<details>
  <summary>Click to see the abstract!</summary>
Directed grey-box fuzzing (DGF) is a security testing technique that aims to steer the fuzzer towards predefined target sites in the program. To gain directness, DGF prioritizes the seeds whose execution traces are closer to the target sites. Therefore, evaluating the distance between the execution trace of a seed and the target sites (aka, the seed distance) is important for DGF. The first directed grey-box fuzzer, AFLGo, uses an approach of calculating the basic block level distances during static analysis and accumulating the distances of the executed basic blocks to compute the seed distance. Following AFLGo, most of the existing state-of-the-art DGF techniques use all the basic blocks on the execution trace and only the control flow information for seed distance calculation. However, not every basic block is equally important and there are certain basic blocks where the execution trace starts to deviate from the target sites (aka, deviation basic blocks).

In this paper, we propose a technique called WindRanger which leverages deviation basic blocks to facilitate DGF. To identify the deviation basic blocks, WindRanger applies both static reachability analysis and dynamic filtering. To conduct directed fuzzing, WindRanger uses the deviation basic blocks and their related data flow information for seed distance calculation, mutation, seed prioritization as well as explore-exploit scheduling. We evaluated WindRanger on 3 datasets consisting of 29 programs. The experiment results show that WindRanger outperforms AFLGo, AFL, and Fairfuzz by reaching the target sites 21%, 34%, and 37% faster and detecting the target crashes 44%, 66%, and 77% faster respectively. Moreover, we found a 0-day vulnerability with a CVE ID assigned in ffmpeg (a popular multimedia library extensively fuzzed by OSS-fuzz) with WindRanger by supplying manually identified suspect locations as the target sites.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [ASIACCS'22] TargetFuzz: Using DARTs to Guide Directed Greybox Fuzzers

[[paper]](https://www.honda-ri.de/pubs/pdf/4940.pdf)

<details>
  <summary>Click to see the abstract!</summary>
Software development is a continuous and incremental process. Developers continuously improve their software in small batches rather than in one large batch. The high frequency of small batches makes it essential to use effective testing methods that detect bugs under limited testing time. To this end, researchers propose directed greybox fuzzing (DGF) which aims to generate test cases towards stressing certain target sites. Different from the coverage-based greybox fuzzing (CGF) which aims to maximize code coverage in the whole program, the goal of DGF is to cover potentially buggy code regions (e.g., a recently modified program region). While prior works improve several aspects of DGF (such as power scheduling, input prioritization, and target selection), little attention has been given to improving the seed selection process. Existing DGF tools use seed corpora mainly tailored for CGF (i.e., a set of seeds that cover different regions of the program). We observe that using CGFbased corpora limits the bug-finding capability of a directed greybox fuzzer. To mitigate this shortcoming, we propose TargetFuzz, a mechanism that provides a DGF tool with a target-oriented seed corpus. We refer to this corpus as DART corpus, which contains only 'close' seeds to the targets. This way, DART corpus guides DGF to the targets, thereby exposing bugs even under limited fuzzing time. Evaluations on 34 real bugs show that AFLGo (a state-of-theart directed greybox fuzzer), when equipped with DART corpus, finds 10 additional bugs and achieves 4.03× speedup, on average, in the time-to-exposure compared to a generic CGF-based corpus.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [S&P'22] Exploit the Last Straw That Breaks Android Systems
  
[[paper]](https://yuanxzhang.github.io/paper/strawfuzzer-oakland22.pdf) [[project]](https://github.com/kekeLian/StrawFuzzer)

<details>
  <summary>Click to see the abstract!</summary>
The Android system services usually play a critical role in running multiple important tasks, and delivering seamless user experiences, e.g., conveniently storing user data. In this paper, we conduct the first systematic security study on the data storing process in Android system services, and consequently discover a novel class of design flaws (named Straw), which can lead to serious DoS (Denial-of-Service) attacks, e.g., permanently crashing the whole victim Android device. Then we propose a novel directed fuzzing based approach, called StrawFuzzer, to automatically vet all system services against the straw vulnerabilities. StrawFuzzer balances the tradeoff between path exploration and vulnerability exploitation. By applying StrawFuzzer on three Android systems with the latest security updates, we identified 35 unique straw vulnerabilities affecting 474 interfaces across 77 system services and successfully generated corresponding exploits, which can be used to conduct various permanent/temporary DoS attacks. We have reported our findings with suggestions for repairing the vulnerabilities to corresponding vendors. Up to now, Google has rated our vulnerability as high severity.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [ICSE'22] Linear-time Temporal Logic guided Greybox Fuzzing
  
[[paper]](https://abhikrc.com/pdf/ICSE22-LTLFuzz.pdf) [[project]](https://github.com/ltlfuzzer/LTL-Fuzzer/) [[talk]](https://www.youtube.com/watch?v=zwAN4uNPs8M)
  
<details>
  <summary>Click to see the abstract!</summary>
Software model checking as well as runtime verification are verification techniques which are widely used for checking temporal properties of software systems. Even though they are property verification techniques, their common usage in practice is in "bug finding", that is, finding violations of temporal properties. Motivated by this observation and leveraging the recent progress in fuzzing, we build a greybox fuzzing framework to find violations
of Linear-time Temporal Logic (LTL) properties.
  
Our framework takes as input a sequential program written in C/C++, and an LTL property. It finds violations, or counterexample traces, of the LTL property in stateful software systems; however, it does not achieve verification. Our work substantially extends directed greybox fuzzing to witness arbitrarily complex event orderings. We note that existing directed greybox fuzzing approaches are limited to witnessing reaching a location or witnessing simple event orderings like use-after-free. At the same time, compared to model checkers, our approach finds the counterexamples faster,
thereby finding more counterexamples within a given time budget.

Our LTL-Fuzzer tool, built on top of the AFL fuzzer, is shown to be effective in detecting bugs in well-known protocol implementations, such as OpenSSL and Telnet. We use LTL-Fuzzer to reproduce known vulnerabilities (CVEs), to find 15 zero-day bugs by checking properties extracted from RFCs (for which 12 CVEs have been assigned), and to find violations of both safety as well as liveness properties in real-world protocol implementations. Our work represents a practical advance over software model checkers — while simultaneously representing a conceptual advance over existing greybox fuzzers. Our work thus provides a starting point for understanding the unexplored synergies among software model checking, runtime verification and greybox fuzzing.
</details>
  
--------------------------------------------------------------------------------------------------------------------------
### [thesis] Directing greybox fuzzing to discover bugs in hardware and software - Sadullah Canakci
  
[[paper]](https://open.bu.edu/bitstream/handle/2144/44702/Canakci_bu_0017E_16967.pdf?sequence=8&isAllowed=y)
  
<details>
  <summary>Click to see the abstract!</summary>
Computer systems are deeply integrated into our daily routines such as online shopping, checking emails, and posting photos on social media platforms. Unfortunately, with the wide range of functionalities and sensitive information stored in computer systems, they have become fruitful targets for attackers. Cybersecurity ventures estimate that the cost of cyber attacks will reach $10.5 trillion USD annually by 2025. Moreover, data breaches have resulted in the leakage of millions of people’s social security numbers, social media account passwords, and healthcare information. With the increasing complexity and connectivity of computer systems, the intensity and volume of cyber attacks will continue to increase. Attackers will continuously look for bugs in the systems and ways to exploit them for gaining unauthorized access or leaking sensitive information. Minimizing bugs in systems is essential to remediate security weaknesses. To this end, researchers proposed a myriad of methods to discover bugs. In the software domain, one prominent method is fuzzing, the process of repeatedly running a program under test with “random” inputs to trigger bugs. Among different variants of fuzzing, greybox fuzzing (GF) has especially seen widespread adoption thanks to its practicality and bug-finding capability. In GF, the fuzzer collects feedback from the program (e.g., code coverage) during its execution and guides the input generation based on the feedback. Due to its success in finding bugs in the software domain, GF has gained traction in the hardware domain as well. Several works adapted GF to the hardware domain by addressing the differences between hardware and software. These works demonstrated that GF can be leveraged to discover bugs in hardware designs such as processors. In this thesis, we propose three different fuzzing mechanisms, one for software and two for hardware, to expose bugs in the multiple layers of systems. Each mechanism focuses on different aspects of GF to assist the fuzzing procedure for triggering bugs in hardware and software. The first mechanism, TargetFuzz, focuses on producing an effective seed corpus when fuzzing software. The seed corpus consists of a set of inputs serving as starting points to the fuzzer. We demonstrate that carefully selecting seeds to steer GF towards potentially buggy code regions increases the bug-finding capability of GF. Compared to prior works, TargetFuzz discovered 10 additional bugs and achieved 4.03× speedup, on average, in the total elapsed time for finding bugs. The second mechanism, DirectFuzz, adapts a specific variant of GF for software fuzzing, namely directed greybox fuzzing (DGF), to the hardware domain. The main use case of DGF in software is patch testing where the goal is to steer fuzzing towards recently modified code region. Similar to software, hardware design is an incremental and continuous process. Therefore, it is important to prioritize testing of a new component in a hardware design rather than previously well-tested components. DirectFuzz takes several differences between hardware and software (such as clock sensitivity, concurrent execution of multiple code fragments, hardware-specific coverage) into account to successfully adapt DGF to the hardware domain. DirectFuzz relies on coverage feedback applicable to a wide range of hardware designs and requires limited design knowledge. While this increases its ease of adoption to many different hardware designs, its effectiveness (i.e., bug-finding success) becomes limited in certain hardware designs such as processors. Overall, compared to a state-of-the-work hardware fuzzer, DirectFuzz covers specified targets sites (e.g., modified hardware regions) 2.23× faster. Our third mechanism named ProcessorFuzz relies on novel coverage feedback tailored for processors to increase the effectiveness of fuzzing in processors. Specifically, ProcessorFuzz monitors value changes in control and status registers which form the backbone of a processor. ProcessorFuzz addresses several drawbacks of existing works in processor fuzzing. Specifically, existing works can introduce significant instrumentation overhead, result in misleading guidance, and have lack of support for widely-used hardware languages. ProcessorFuzz revealed 8 new bugs in widely-used open source processors and identified bugs 1.23× faster than a prior work.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [Usenix'22] BRAKTOOTH: Causing Havoc on Bluetooth Link Manager via Directed Fuzzing
  
[[paper]](https://asset-group.github.io/papers/BrakTooth.pdf) [[project]](https://github.com/Matheus-Garbelini/braktooth_esp32_bluetooth_classic_attacks)

<details>
  <summary>Click to see the abstract!</summary>
In this paper we propose, design and evaluate a systematic directed fuzzing framework to automatically discover implementation bugs in arbitrary Bluetooth Classic (BT) devices. The core of our fuzzer is the first over-the-air approach that takes full control of the BT controller baseband from the host. This enables us to intercept and modify arbitrary packets, as well as to inject packets out-of-order in lower layers of closed-source BT stack, i.e., Link Manager Protocol (LMP) and Baseband. To systematically guide our fuzzing process, we propose an extensible and novel rule-based approach to automatically construct the protocol state machine during normal over-the-air communication. In particular, by writing a simple set of rules to identify protocol messages, we can dynamically construct an abstracted protocol state machine, fuzz packets resulting from a state and validate responses from target devices. As of today, we have fuzzed 13 BT devices from 11 vendors and we have discovered a total of 18 unknown implementation flaws, with 24 common vulnerability exposures (CVEs) assigned. Furthermore, our discoveries were awarded with six bug bounties from certain vendors. Finally, to show
the broader applicability of our framework beyond BT, we have extended our approach to fuzz other wireless protocols, which additionally revealed 6 unknown bugs in certain Wi-Fi and BLE Host stacks.
</details>
  
--------------------------------------------------------------------------------------------------------------------------
### [arxiv'22] Multiple Targets Directed Greybox Fuzzing
  
[[paper]](https://arxiv.org/pdf/2206.14977.pdf) [[project]](https://github.com/HongliangLiang/leofuzz)

<details>
  <summary>Click to see the abstract!</summary>
Directed greybox fuzzing (DGF) can quickly discover or reproduce bugs in programs by seeking to reach a program location or explore some locations in order. However, due to their static stage division and coarse-grained energy scheduling, prior DGF tools perform poorly when facing multiple target locations (targets for short). In this paper, we present multiple targets directed greybox fuzzing which aims to reach multiple programs locations in a fuzzing campaign. Specifically, we propose a novel strategy to adaptively coordinate exploration and exploitation stages, and a novel energy scheduling strategy by considering more relations between seeds and target locations. We implement our approaches in a tool called LeoFuzz and evaluate it on crash reproduction, true positives verification, and vulnerability exposure in real-world programs. Experimental results show that LeoFuzz outperforms six state-of-the-art fuzzers, i.e., QYSM, AFLGo, Lolly, Berry, Beacon and WindRanger in terms of effectiveness and efficiency. Moreover, LeoFuzz has detected 23 new vulnerabilities in real-world programs, and 11 of them have been assigned CVE IDs.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [arxiv'22] FishFuzz: Throwing Larger Nets to Catch Deeper Bugs
  
[[paper]](https://arxiv.org/pdf/2207.13393.pdf) [[project]](https://zenodo.org/record/6405418#.YuzNvexBz_o)

<details>
  <summary>Click to see the abstract!</summary>
Greybox fuzzing is the de-facto standard to discover bugs during development. Fuzzers execute many inputs to maximize the amount of reached code. Recently, Directed Greybox Fuzzers (DGFs) propose an alternative strategy that goes beyond “just” coverage: driving testing toward specific code targets by selecting “closer” seeds. DGFs go through different phases: exploration (i.e., reaching interesting locations) and exploitation (i.e., triggering bugs). In practice, DGFs leverage coverage to directly measure exploration, while exploitation is, at best, measured indirectly by alternating between different targets. Specifically, we observe two limitations in existing DGFs: (i) they lack precision in their distance metric, i.e., averaging multiple
paths and targets into a single score (to decide which seeds to prioritize), and (ii) they assign energy to seeds in a round-robin fashion without adjusting the priority of the targets (exhaustively explored targets should be dropped).
  
We propose FishFuzz, which draws inspiration from trawl fishing: first casting a wide net, scraping for high coverage, then slowly pulling it in to maximize the harvest. The core of our fuzzer is a novel seed selection strategy that builds on two concepts: (i) a novel multi-distance metric whose precision is independent of the number of targets, and (ii) a dynamic target ranking to automatically discard exhausted targets. This strategy allows FishFuzz to seamlessly scale to tens of thousands of targets and dynamically alternate between exploration and exploitation phases. We evaluate FishFuzz by leveraging all sanitizer labels as targets. Extensively comparing FishFuzz against modern DGFs and coverage-guided fuzzers shows that FishFuzz reached higher coverage compared to the direct competitors, reproduces existing bugs (70.2% faster), and finally discovers 25 new bugs (18 CVEs) in 44 programs.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [CCS'22] MC2: Rigorous and Efficient Directed Greybox Fuzzing
  
[[paper]](https://arxiv.org/pdf/2208.14530.pdf) [[project]](https://hub.docker.com/r/abhishekshah212/mc2)

<details>
  <summary>Click to see the abstract!</summary>
Directed greybox fuzzing is a popular technique for targeted software testing that seeks to find inputs that reach a set of target sites in a program. Most existing directed greybox fuzzers do not provide any theoretical analysis of their performance or optimality. In this paper, we introduce a complexity-theoretic framework to pose directed greybox fuzzing as a oracle-guided search problem where some feedback about the input space (e.g., how close an input is to the target sites) is received by querying an oracle. Our framework assumes that each oracle query can return arbitrary content with a large but constant amount of information. Therefore, we use the number of oracle queries required by a fuzzing algorithm to find a target-reaching input as the performance metric. Using our framework, we design a randomized directed greybox fuzzing algorithm that makes a logarithmic (wrt. the number of all possible inputs) number of queries in expectation to find a target-reaching input. We further prove that the number of oracle queries required
by our algorithm is optimal, i.e., no fuzzing algorithm can improve (i.e., minimize) the query count by more than a constant factor. We implement our approach in MC2 and outperform state-of-theart directed greybox fuzzers on challenging benchmarks (Magma and Fuzzer Test Suite) by up to two orders of magnitude (i.e., 134×) on average. MC2 also found 15 previously undiscovered bugs that other state-of-the-art directed greybox fuzzers failed to find.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [ACSAC'22] One Fuzz Doesn’t Fit All: Optimizing Directed Fuzzing via Target-tailored Program State Restriction
  
[[paper]](https://hexhive.epfl.ch/publications/files/22ACSAC2.pdf) [[project]](https://github.com/HexHive/SieveFuzz)

<details>
  <summary>Click to see the abstract!</summary>
Fuzzing is the de-facto default technique to discover software flaws, randomly testing programs to discover crashing test cases. Yet, a particular scenario may only care about specific code regions (for, e.g., bug reproduction, patch or regression testing)—spurring the adoption of directed fuzzing. Given a set of pre-determined target locations, directed fuzzers drive exploration toward them through distance minimization strategies that (1) isolate the closest-reaching test cases and (2) mutate them stochastically. However, these strategies are applied onto every explored test case—irrespective of whether they ever reach the targets—stalling progress on the paths where targets are unreachable. Accelerating directed fuzzing requires prioritizing target-reachable paths.

To overcome the bottleneck of wasteful exploration in directed fuzzing, we introduce tripwiring: a lightweight technique to preempt and terminate the fuzzing of paths that will never reach target locations. By constraining exploration to only the set of target-reachable program paths, tripwiring curtails directed fuzzers’ search noise—while unshackling them from the high-overhead instrumentation and bookkeeping of distance minimization—enabling
directed fuzzers to obtain up to 99× higher test case throughput. We implement tripwiring-directed fuzzing as a prototype, SieveFuzz, and evaluate it alongside the state-of-the-art directed fuzzers AFLGo, BEACON and the leading undirected fuzzer AFL++. Overall, across nine benchmarks, SieveFuzz’s tripwiring enables it to trigger bugs on an average 47% more consistently and 117% faster than AFLGo, BEACON and AFL++.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [S&P'23] SELECTFUZZ: Efficient Directed Fuzzing with Selective Path Exploration

[[paper]](https://csdl-downloads.ieeecomputer.org/proceedings/sp/2023/9336/00/933600b050.pdf?Expires=1672859666&Policy=eyJTdGF0ZW1lbnQiOlt7IlJlc291cmNlIjoiaHR0cHM6Ly9jc2RsLWRvd25sb2Fkcy5pZWVlY29tcHV0ZXIub3JnL3Byb2NlZWRpbmdzL3NwLzIwMjMvOTMzNi8wMC85MzM2MDBiMDUwLnBkZiIsIkNvbmRpdGlvbiI6eyJEYXRlTGVzc1RoYW4iOnsiQVdTOkVwb2NoVGltZSI6MTY3Mjg1OTY2Nn19fV19&Signature=IHxAaMfG4NH8KIS~~p~jcceRLTaa2g~ycPozrqmd32BjBgMJubIjijrHoqnFJajhk0yEQgQXsf8z4PzsWXSV4XpI1m6AbpVYDib-YC6nr3DHheezNDdWFkwv8vI2jcMuxBsRU7mgZ7hT89YtD1OM1USnlaEXmzfPVJ~o0AJKD44isdnfnIPNLo2u~pIme04mFmR-xP~k8TMv-44jQ6O~ktmABwsR2TEY9dPL7BZI8BgOMqVXFciFiAMN5nfbT8qcWP0zDajFXl4Dv1cGL0axOFx-fnxARaNeTIXFGpad8aNV0uFcWKAGvZSKRnJv9WFiK5Ya57MjvUT217i4~1ZYnQ__&Key-Pair-Id=K12PMWTCQBDMDT) [[project]](https://github.com/cuhk-seclab/SelectFuzz)

<details>
  <summary>Click to see the abstract!</summary>
Directed grey-box fuzzers specialize in testing specific target code. They have been applied to many security applications such as reproducing known crashes and detecting vulnerabilities caused by incomplete patches. However, existing directed fuzzers favor the inputs discovering new code regardless whether the newly uncovered code is relevant to the target code or not. As a result, the fuzzers would extensively explore irrelevant code and
suffer from low efficiency. In this paper, we distinguish relevant code in the target program from the irrelevant one that does not help trigger the vulnerabilities in target code. We present SELECTFUZZ, a new directed fuzzer that selectively explores relevant program paths for efficient crash reproduction and vulnerability detection. It identifies two types of relevant code—path-divergent code and data-dependent code, that respectively captures the controland data-dependency with the target code. It then selectively instruments and explores only the relevant code blocks. We also propose a new distance metric that accurately measures the reaching probability of different program paths and inputs. We evaluated SELECTFUZZ with real-world vulnerabilities in sets of diverse programs. SELECTFUZZ significantly outperformed a baseline directed fuzzer by up to 46.31×, and performed the best in the Google Fuzzer Test Suite. Our experiments also demonstrated that SELECTFUZZ and the existing techniques such as path pruning are complementary. Finally, with SELECTFUZZ, we detected 14 previously unknown vulnerabilities—including 6 new CVE IDs—in well tested real-world software. Our report has led to the fix of 11 vulnerabilities.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [TDSC'23] G-Fuzz: A Directed Fuzzing Framework for gVisor

[[paper]](https://ieeexplore.ieee.org/abstract/document/10049484) [[project]](https://github.com/zjuchenyuan/gfuzz)

<details>
  <summary>Click to see the abstract!</summary>
gVisor is a Google-published application-level kernel for containers. As gVisor is lightweight and has sound isolation, it has been widely used in many IT enterprises. When a new vulnerability of the upstream gVisor is found, it is important for the downstream developers to test the corresponding code to maintain the security. To achieve this aim, directed fuzzing is promising. Nevertheless, there are many challenges in applying existing directed fuzzing methods for gVisor. The core reason is that existing directed fuzzers are mainly for general C/C++ applications, while gVisor is an OS kernel written in the Go language. To address the above challenges, we propose G-Fuzz, a directed fuzzing framework for gVisor. There are three core methods in G-Fuzz, including lightweight and fine-grained distance calculation, target related syscall inference and utilization, and exploration and exploitation dynamic switch. Note that the methods of G-Fuzz are general and can be transferred to other OS kernels. We conduct extensive experiments to evaluate the performance of G-Fuzz. Compared to Syzkaller, the state-of-the-art kernel fuzzer, G-Fuzz outperforms it significantly. Furthermore, we have rigorously evaluated the importance for each core method of G-Fuzz. G-Fuzz has been deployed in industry and has detected multiple serious vulnerabilities.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [arxiv'23] Directed Greybox Fuzzing with Stepwise Constraint Focusing

[[paper]](https://arxiv.org/pdf/2303.14895.pdf)

<details>
  <summary>Click to see the abstract!</summary>
Dynamic data flow analysis has been widely used to guide greybox fuzzing. However, traditional dynamic data flow analysis tends to go astray in the massive path tracking and requires to process a large volume of data, resulting in low efficiency in reaching the target location. In this paper, we propose a directed greybox fuzzer based on dynamic constraint filtering and focusing (CONFF). First, all path constraints are tracked, and those with high priority are filtered as the next solution targets. Next, focusing on a single path constraint to be satisfied, we obtain its data condition and probe the mapping relationship between it and the input bytes through multi-byte mapping and single-byte mapping. Finally, various mutation strategies are utilized to solve the path constraint currently focused on, and the target location of the program is gradually approached through path selection. The CONFF fuzzer can reach a specific location faster in the target program, thus efficiently triggering the crash.

We designed and implemented a prototype of the CONFF fuzzer and evaluated it with the LAVA-1 dataset and some real-world vulnerabilities. The results show that the CONFF fuzzer can reproduce crashes on the LAVA-1 dataset and most of the real-world vulnerabilities. For most vulnerabilities, the CONFF fuzzer reproduced the crashes with significantly reduced time compared to state-of-the-art fuzzers. On average, the CONFF fuzzer was 23.7x faster than the state-of-the-art code coverage-based fuzzer Angora and 27.3x faster than the classical directed greybox fuzzer AFLGo.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [S&P'23] ODDFUZZ: Discovering Java Deserialization Vulnerabilities via Structure-Aware Directed Greybox Fuzzing

[[paper]](https://arxiv.org/pdf/2304.04233.pdf) [[project]](https://github.com/ODDFuzz/ODDFuzz)

<details>
  <summary>Click to see the abstract!</summary>
Java deserialization vulnerability is a severe threat in practice. Researchers have proposed static analysis solutions to locate candidate vulnerabilities and fuzzing solutions to generate proof-of-concept (PoC) serialized objects to trigger them. However, existing solutions have limited effectiveness and efficiency. In this paper, we propose a novel hybrid solution ODDFUZZ to efficiently discover Java deserialization vulnerabilities. First, ODDFUZZ performs lightweight static taint analysis to identify candidate gadget chains that may cause deserialization vulnerabilities. In this step, ODDFUZZ tries to locate all candidates and avoid false negatives. Then, ODDFUZZ performs directed greybox fuzzing (DGF) to explore those candidates and generate PoC testcases to mitigate false positives. Specifically, ODDFUZZ applies a structure-aware seed generation method to guarantee the validity of the testcases, and adopts a novel hybrid feedback and a step-forward strategy to guide the directed fuzzing.

We implemented a prototype of ODDFUZZ and evaluated it on the popular Java deserialization repository ysoserial. Results show that, ODDFUZZ could discover 16 out of 34 known gadget chains, while two state-of-the-art baselines only identify three of them. In addition, we evaluated ODDFUZZ on real-world applications including Oracle WebLogic Server, Apache Dubbo, Sonatype Nexus, and protostuff, and found six previously unreported exploitable gadget chains with five CVEs assigned.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [IET Software'23] CIDFuzz: Fuzz testing for continuous integration

[[paper]](https://ietresearch.onlinelibrary.wiley.com/doi/pdf/10.1049/sfw2.12125)

<details>
  <summary>Click to see the abstract!</summary>
As agile software development and extreme programing have become increasingly popular, continuous integration (CI) has become a widely used collaborative work method. However, it is common to make changes frequently to a project during CI. If existing testing methods are applied to CI directly, it will be difficult to make testing resources focus on changes generated by CI, which results in insufficient testing for changes. To solve this problem, we propose a fuzz testing method for CI. First, differential analysis is performed to determine the change points generated during CI, change points are added to the taint source set, and static analysis is conducted to calculate the distances between each basic block and the taint sources. Then, the project under test is instrumented according to the distances. During fuzz testing, testing resources are allocated based on seed coverage to test the change points effectively. Using the proposed methods, we implement CIDFuzz as a prototype tool, and experiments are conducted on four open‐source projects that use CI. Experimental results show that, compared with AFL and AFLGo, CIDFuzz can reduce the time costs of covering change points up to 39.59% and 41.64%, respectively. Also, CIDFuzz can reduce the time costs of reproducing vulnerabilities up to 34.78% and 25.55%.
</details>
  
--------------------------------------------------------------------------------------------------------------------------
### [EuroS&P'23] Hunting for Truth: Analyzing Explanation Methods in Learning-based Vulnerability Discovery

[[paper]](https://mlsec.org/docs/2023-eurosp.pdf)

<details>
  <summary>Click to see the abstract!</summary>
Recent research has developed a series of methods for finding vulnerabilities in software using machine learning. While the proposed methods provide a remarkable performance in controlled experiments, their practical application is hampered by their black-box nature: A security practitioner cannot tell how these methods arrive at a decision and what code structures contribute to a reported security flaw. Explanation methods for machine learning may overcome this problem and guide the practitioner to relevant code. However, there exist a variety of competing explanation methods, each highlighting different code regions when given the same finding. So far, this inconsistency has made it impossible to select a suitable explanation method for practical use.
  
In this paper, we address this problem and develop a method for analyzing and comparing explanations for learning-based vulnerability discovery. Given a predicted vulnerability, our approach uses directed fuzzing to create local ground-truth around code regions marked as relevant by an explanation method. This local ground-truth enables us to assess the veracity of the explanation. As a result, we can qualitatively compare different explanation methods and determine the most accurate one for a particular learning setup. In an empirical evaluation with different discovery and explanation methods, we demonstrate the utility of this approach and its capabilities in making learning-based vulnerability discovery more transparent.
</details>
  
--------------------------------------------------------------------------------------------------------------------------
### [ISSTA'23] 1dFuzz: Reproduce 1-day Vulnerabilities with Directed Differential Fuzzing

[[paper]](https://dl.acm.org/doi/pdf/10.1145/3597926.3598102)

<details>
  <summary>Click to see the abstract!</summary>
1-day vulnerabilities are common in practice and have posed severe threats to end users, as adversaries could learn from released patches to find them and exploit them. Reproducing 1-day vulnerabilities is also crucial for defenders, e.g., to block attack traffic against 1-day vulnerabilities. A core question that affects the effectiveness of recognizing and triggering 1-day vulnerabilities is what is the unique feature of a security patch. After conducting a large-scale empirical study, we point out that a common and unique feature of patches is the trailing call sequence (TCS) and present a novel directed differential fuzzing solution 1dFuzz to efficiently reproduce 1-day vulnerabilities in this paper. Based on the TCS feature, we present a locator 1dLoc able to find candidate patch locations via static analysis, a novel TCS-based distance metric for directed fuzzing, and a novel sanitizer 1dSan able to catch PoCs for 1-day vulnerabilities during fuzzing. We have systematically evaluated 1dFuzz on a set of real-world software vulnerabilities in 11 different settings. Results show that 1dFuzz significantly outperforms state-of-the-art (SOTA) baselines and could find up to 2.26x more 1-day vulnerabilities with a 43% shorter time.
</details>
  
--------------------------------------------------------------------------------------------------------------------------
### [Usenix'23] FishFuzz: Catch Deeper Bugs by Throwing Larger Nets

[[paper]](https://nebelwelt.net/files/23SEC5.pdf) [[project]](https://github.com/HexHive/FishFuzz) [[artifact]](https://zenodo.org/record/6405418) 
  
<details>
  <summary>Click to see the abstract!</summary>
Fuzzers effectively explore programs to discover bugs. Greybox fuzzers mutate seed inputs and observe their execution. Whenever a seed reaches new behavior (e.g., new code or higher execution frequency), it is stored for further mutation. Greybox fuzzers directly measure exploration and, by repeating execution of the same targets with large amounts of mutated seeds, passively exploit any lingering bugs. Directed greybox fuzzers (DGFs) narrow the search to a few code locations but so far generalize distance to all targets into a single score and do not prioritize targets dynamically.

FISHFUZZ introduces an input prioritization strategy that builds on three concepts: (i) a novel multi-distance metric whose precision is independent of the number of targets, (ii) a dynamic target ranking to automatically discard exhausted targets, and (iii) a smart queue culling algorithm, based on hyperparameters, that alternates between exploration and exploitation. FISHFUZZ enables fuzzers to seamlessly scale among thousands of targets and prioritize seeds toward interesting locations, thus achieving more comprehensive program testing. To demonstrate generality, we implement FISHFUZZ over two well-established greybox fuzzers (AFL and AFL++). We evaluate FISHFUZZ by leveraging all sanitizer labels as targets. In comparison to modern DGFs and state-of-the-art coverage guided fuzzers, FISHFUZZ reaches higher coverage compared to the direct competitors, finds up to 2.8x more
bugs compared with the baseline and reproduces 68.3% existing bugs faster. FISHFUZZ also discovers 56 new bugs (38 CVEs) in 47 programs.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [arxiv'23] FGo: A Directed Grey-box Fuzzer with Probabilistic Exponential cut-the-loss Strategies

[[paper]](https://arxiv.org/pdf/2307.05961.pdf) [[project]](https://github.com/harvey-lau/fgo) 
  
<details>
  <summary>Click to see the abstract!</summary>
Traditional coverage grey-box fuzzers perform a breadth-first search of the state space of Program Under Test (PUT). This aimlessness wastes a lot of computing resources. Directed grey-box fuzzing focuses on the target of PUT and becomes one of the most popular topics of software testing. The early termination of unreachable test cases is a method to improve directed grey-box fuzzing. However, existing solutions have two problems: firstly, reachability analysis needs to introduce extra technologies (e.g., static analysis); secondly, the performance of reachability analysis and auxiliary technologies lack versatility.

We propose FGo, a probabilistic exponential cutthe-loss directed grey-box fuzzer. FGo terminates unreachable test cases early with exponentially increasing probability. Compared to other technologies, FGo makes full use of the unreachable information contained in iCFG and doesn‘t generate any additional overhead caused by reachability analysis. Moreover, it is easy to generalize to all PUT. This strategy based on probability is perfectly adapted to the randomness of fuzzing.

The experiment results show that FGo is 106% faster than AFLGo in reproducing crashes. We compare multiple parameters of probabilistic exponential cut-the-loss algorithm and analyze them in detail. In addition, for enhancing the interpretability of FGo, this paper discusses the difference between the theoretical performance and the practical performance of
probabilistic exponential cut-the-loss algorithm.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [Usenix'23] DAFL: Directed Grey-box Fuzzing Guided by Data Dependency

[[paper]](https://prosys.kaist.ac.kr/publications/sec23.pdf) [[project]](https://github.com/prosyslab/DAFL-artifact) [[artifact]](https://zenodo.org/record/8031029) [[slides]](https://www.usenix.org/system/files/sec23_slides_kim-tae.pdf)
  
<details>
  <summary>Click to see the abstract!</summary>
Despite growing research interest, existing directed greybox fuzzers do not scale well with program complexity. In this paper, we identify two major scalability challenges for
current directed grey-box fuzzing. Particularly, we find that traditional coverage feedback does not always provide meaningful guidance for reaching the target program point(s), and
the existing seed distance mechanism does not operate well with programs with complex control structures. To address these problems, we present a novel fuzzer, named DAFL. DAFL selects code parts that are relevant to the target location and obtains coverage feedback only from those parts. Furthermore, it computes precise seed distances considering the data-flow semantics of program executions. The results are promising. Out of 41 real-world bugs, DAFL was able to find 4, 6, 9, and 5 more bugs within the given time, compared to AFL, AFLGo, WindRanger, and Beacon, respectively. Furthermore, among the cases where all fuzzers produced a median TTE, DAFL was at least 4.99 times faster on average compared to 3 state-of-the-art directed fuzzers including AFLGo, WindRanger, and Beacon.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [EuroS&PW 2023'23] Guiding Directed Fuzzing with Feasibility

[[paper]](https://www.computer.org/csdl/proceedings-article/eurospw/2023/272000a042/1OFtf6ngcTe)
  
<details>
  <summary>Click to see the abstract!</summary>
Directed fuzzing is a useful technique that can confirm bugs found by static analysis, reproduce existing bugs, and efficiently test code changes. A general mechanism in directed fuzzing is to calculate the distance between the current progress and the target, and use that as a feedback to guide the directed fuzzing. A fundamental problem with existing distance calculation is that it is feasibility-unaware. For instance, it always assumes that the two branches of an if statement have equal feasibility, which is likely not true in real-world programs and would inevitablly incur significant biases in the directed fuzzing. In this work, we propose feasibility-aware directed fuzzing, AFLGopher. Our new feasibility-aware distance calculation provides precise feedback to guide directed fuzzing to reach targets efficiently. We propose new techniques to address challenges of the feasibility prediction. Our new classification method allows to predict the feasibility of all branches based on limited traces, and our runtime feasibility-updating mechanism gradually improves the prediction precision. We implement AFLGopher, and the evaluation results show that AFLGopher uses less time to reach the bugs, compared to the state of the art.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [CCS'23] HyperGo: Probability-based Directed Hybrid Fuzzing

[[paper]](https://arxiv.org/pdf/2307.07815.pdf) [[project]](https://gitee.com/paynelin/hypergo)
  
<details>
  <summary>Click to see the abstract!</summary>
Directed grey-box fuzzing (DGF) is a target-guided fuzzing intended for testing specific targets (e.g., the potential buggy code). Despite numerous techniques proposed to enhance directedness, the existing DGF techniques still face challenges, such as taking into account the difficulty of reaching different basic blocks when designing the fitness metric, and promoting the effectiveness of symbolic execution (SE) when solving the complex constraints in the path to the target. In this paper, we propose a directed hybrid fuzzer called
HyperGo. To address the challenges, we introduce the concept of path probability and combine the probability with distance to form an adaptive fitness metric called probability-based distance. By combining the two factors, probability-based distance can adaptively guide DGF toward paths that are closer to the target and have more easy-to-satisfy path constraints. Then, we put forward an Optimized Symbolic Execution Complementary (OSEC) scheme to combine DGF and SE in a complementary manner. The OSEC would prune the unreachable branches and unsolvable branches, and prioritize symbolic execution of the seeds whose paths are closer to the target and have more branches that are difficult to be covered by DGF. We evaluated HyperGo on 2 benchmarks consisting of 21 programs with a total of 100 target sites. The experimental results show that HyperGo achieves 38.47×, 30.89×, 28.52×, 106.09× and 143.22× speedup compared to AFLGo, AFLGoSy, BEACON, WindRanger, and ParmeSan, respectively in reaching target sites, and 3.44×, 3.63×, 4.10×, 3.26×, and 3.00× speedup in exposing known
vulnerabilities. Moreover, HyperGo discovered 37 undisclosed vulnerabilities from 7 real-world programs.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [CCS'23] SyzDirect: Directed Greybox Fuzzing for Linux Kernel


  
<details>
  <summary>Click to see the abstract!</summary>
Bug reports and patch commits are dramatically increasing for OS kernels, incentivizing a critical need for kernel-level bug reproduction and patch testing. Directed greybox fuzzing (DGF), aiming to stress-test a specific part of code, is a promising approach for bug reproduction and patch testing. However, the existing DGF methods exclusively target user-space applications, presenting intrinsic limitations in handling OS kernels. In particular, these methods cannot pinpoint the appropriate system calls and the needed syscall parameter values to reach the target location, resulting in low efficiency and waste of resources.

In this paper, we present SyzDirect, a DGF solution for the Linux kernel. With a novel, scalable static analysis of the Linux kernel, SyzDirect identifies valuable information such as correct system calls and conditions on their arguments to reach the target location. During fuzzing, SyzDirect utilizes the static analysis results to guide the generation and mutation of test cases, followed by leveraging distance-based feedback for seed prioritization and power scheduling. We evaluated SyzDirect on upstream Linux kernels for bug reproduction and patch testing. The results show that SyzDirect can reproduce 320% more bugs and reach 25.6% more target patches than generic kernel fuzzers. It also improves the speed of bug reproduction and patch reaching by a factor of 154.3 and 680.9, respectively.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [MS Thesis'23] Hybrid Testing: Combining Static Analysis and Directed Fuzzing

[[paper]](https://dspace.mit.edu/bitstream/handle/1721.1/151679/shields-pshields-meng-eecs-2023-thesis.pdf?sequence=1&isAllowed=y)

<details>
  <summary>Click to see the abstract!</summary>
New CVEs are discovered each year and their underlying bugs leave applications vulnerable to exploitation. Software is still frequently written in bug prone languages, e.g. C and C++,
and a single missed check during manual testing can result in vulnerabilities. Existing automated testing tools such as fuzzing are limited in scope or in the case of static analysis, have a high false positive rate. Without improved automated testing, it can be challenging for developers to debug large, complex codebases. In this paper, Hybrid Testing is presented
as a solution. Hybrid Testing combines static and dynamic analyses, leveraging static analysis to perform complex reasoning about logic, memory management, and concurrency. It creates a novel orchestration system which allows us to automatically verify the output of static analysis tools using directed fuzzing. Hybrid Testing is the first vulnerability detection technique with full codebase coverage and no false positives. It can be seamlessly integrated into the development cycle and scales well to large codebases. This work details the design and implementation of Hybrid Testing and evaluates its performance across a corpus of open-source C and C++ applications in the Magma benchmark. Hybrid Testing aims to promote more secure software through rigorous testing, making it easier for developers to detect security issues. We demonstrate Hybrid Testing can find vulnerabilities up to 25% faster with 17% higher accuracy (when detecting additional bugs) than current automated testing strategies.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [Usenix'23] DDRace: Finding Concurrency UAF Vulnerabilities in Linux Drivers with Directed Fuzzing

[[paper]](https://www.usenix.org/system/files/usenixsecurity23-yuan-ming.pdf) [[slides]](https://www.usenix.org/system/files/sec23_slides_yuan.pdf) [[project]](https://github.com/vul337/DDRace)

<details>
  <summary>Click to see the abstract!</summary>
Concurrency use-after-free (UAF) vulnerabilities account for a large portion of UAF vulnerabilities in Linux drivers. Many solutions have been proposed to find either concurrency bugs
or UAF vulnerabilities, but few of them can be directly applied to efficiently find concurrency UAF vulnerabilities. In this paper, we propose the first concurrency directed greybox
fuzzing solution DDRace to discover concurrency UAF vulnerabilities efficiently in Linux drivers. First, we identify candidate use-after-free locations as target sites and extract the relevant concurrency elements to reduce the exploration space of directed fuzzing. Second, we design a novel vulnerabilityrelated distance metric and an interleaving priority scheme
to guide the fuzzer to better explore UAF vulnerabilities and thread interleavings. Lastly, to make test cases reproducible, we design an adaptive kernel state migration scheme to assist continuous fuzzing. We have implemented a prototype of DDRace, and evaluated it on upstream Linux drivers. Results show that DDRace is effective at discovering concurrency
use-after-free vulnerabilities. It finds 4 unknown vulnerabilities and 8 known ones, which is more effective than other state-of-the-art solutions.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [arxiv'23] TOPr: Enhanced Static Code Pruning for Fast and Precise Directed Fuzzing

[[paper]](https://arxiv.org/pdf/2309.09522.pdf)

<details>
  <summary>Click to see the abstract!</summary>
Directed fuzzing is a dynamic testing technique that focuses exploration on specific, pre-targeted program locations. Like other types of fuzzers, directed fuzzers are most effective when maximizing testing speed and precision. To this end, recent directed fuzzers have begun leveraging path pruning: preventing the wasteful testing of program paths deemed irrelevant to reaching a desired target location. Yet, despite code pruning’s substantial speedup, current approaches are imprecise—failing to capture indirect control flow—requiring additional dynamic analyses that diminish directed fuzzers’ speeds. Thus, without code pruning that is both fast and precise, directed fuzzers’
effectiveness will continue to remain limited.

This paper aims to tackle the challenge of upholding both speed and precision in pruning-based directed fuzzing. We show that existing pruning approaches fail to recover common-case indirect control flow; and identify opportunities to enhance them with lightweight heuristics—namely, function signature matching—enabling them to maximize precision without the burden of dynamic analysis. We implement our enhanced pruning as a prototype, TOPr (Target Oriented Pruning), and evaluate it against the leading pruning-based and pruning-agnostic directed fuzzers SieveFuzz and AFLGo. We show that TOPr’s enhanced pruning outperforms these fuzzers in (1) speed (achieving 222%
and 73% higher test case throughput, respectively); (2) reachability (achieving 149% and 9% more target-relevant coverage, respectively); and (3) bug discovery time (triggering bugs faster 85% and 8%, respectively). Furthermore, TOPr’s balance of speed and precision enables it to find 24 new bugs in 5 opensource applications, with 18 confirmed by developers, 12 bugs labelled as “Priority - 1. High”, and 12 bugs fixed — underscoring the effectiveness of our framework.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [S&P'24] Titan : Efficient Multi-target Directed Greybox Fuzzing

[[paper]](https://5hadowblad3.github.io/files/Oakland24-Titan.pdf) [[project]](https://github.com/5hadowblad3/Titan)

<details>
  <summary>Click to see the abstract!</summary>
Modern directed fuzzing often faces scalability issues when analyzing multiple targets in a program simultaneously. We observe that the root cause is that directed fuzzers are unaware of the correlations among the targets, thereby could degenerate into a target-undirected method. As a result, directed fuzzing suffers severely from efficiency when reproducing multiple targets. This paper presents Titan, which enables fuzzers to distinguish correlations among various targets in the program and, thus, optimizes the input generation to reproduce multiple targets effectively. Leveraging these correlations, Titan differentiates seeds’ potential of reaching each target for the scheduling and identifies bytes that can be changed simultaneously for the mutation. We compare our approach to eight state-of-the-art (directed) fuzzers. The evaluation demonstrates that Titan outperforms existing approaches by efficiently detecting multiple targets, achieving a 21.4x speedup and requiring 95.0% fewer number of executions. In addition, Titan detects ten incomplete fixes, which cannot be detected by other directed fuzzers, in the latest versions of the benchmark programs with two CVE IDs assigned.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [arxiv'23] Toward Unbiased Multiple-Target Fuzzing with Path Diversity

[[paper]](https://arxiv.org/pdf/2310.12419.pdf)

<details>
  <summary>Click to see the abstract!</summary>
Directed fuzzing is an advanced software testing approach that systematically guides the fuzzing campaign toward userdefined target sites, enabling efficient discovery of vulnerabilities related to these sites. However, we have observed that some complex vulnerabilities remain undetected by directed fuzzers even when the flawed target sites are frequently tested by the generated test cases, because triggering these bugs often requires the execution of additional code in related program locations. Furthermore, when fuzzing multiple targets, the existing energy assignment in directed fuzzing lacks precision and does not ensure the fairness across targets, which leads to insufficient fuzzing effort spent on some deeper targets.

  In this paper, we propose a novel directed fuzzing solution named AFLRUN, which features target path-diversity metric and unbiased energy assignment. Firstly, we develop a new coverage metric by maintaining extra virgin map for each covered target to track the coverage status of seeds that hit the target. This approach enables the storage of waypoints into the corpus that hit a target through interesting path, thus enriching the path diversity for each target. Additionally, we propose a corpus-level energy assignment strategy that guarantees fairness for each target. AFLRUN starts with uniform target weight and propagates this weight to seeds to get a desired seed weight distribution. By assigning energy to each seed in the corpus according to such desired distribution, a precise and unbiased energy assignment can be achieved. We built a prototype system and assessed its performance
using a standard benchmark and several extensively fuzzed real-world applications. The evaluation results demonstrate that AFLRUN outperforms state-of-the-art fuzzers in terms of vulnerability detection, both in quantity and speed. Moreover, AFLRUN uncovers 29 previously unidentified vulnerabilities, including 8 CVEs, across four distinct programs.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [S&P'24] Predecessor-aware Directed Greybox Fuzzing

[[paper]](https://csdl-downloads.ieeecomputer.org/proceedings/sp/2024/3130/00/313000a040.pdf?Expires=1697899812&Policy=eyJTdGF0ZW1lbnQiOlt7IlJlc291cmNlIjoiaHR0cHM6Ly9jc2RsLWRvd25sb2Fkcy5pZWVlY29tcHV0ZXIub3JnL3Byb2NlZWRpbmdzL3NwLzIwMjQvMzEzMC8wMC8zMTMwMDBhMDQwLnBkZiIsIkNvbmRpdGlvbiI6eyJEYXRlTGVzc1RoYW4iOnsiQVdTOkVwb2NoVGltZSI6MTY5Nzg5OTgxMn19fV19&Signature=LEITvnw-OMz5UAvIPZXULOlWq3PUn1CfR0eAZnoiT7fdA5aGG4N-TPe7~2zND9a~9jmXqB4TpXI0xjwOH3628~39Gx6SthTI2T-7iRF1v439a8l9sJ9Qr~51R7rm1QjAPrsz-fuw0OKpSqKlUDQsezvzoSvm-~F3w~7skklcwPT5fKJjc6i85FeRYEBxgdrDGvJOqhdt~f~SLsFnXkj6xcTQOSOn6X8rKgiI6pmYh5jAcQUEHRprkqHXB8eg0fn-ZhWQ-~eGCzpUpgl4KHQ6-9cmUBY-tvX6JtL72H7QaFr7kciFs0G9T8pSG8sNZCd-5tJvW4LTWL35RlE5ZKhMCQ__&Key-Pair-Id=K12PMWTCQBDMDT) [[project]](https://github.com/SEU-SSL/PDGF)

<details>
  <summary>Click to see the abstract!</summary>
Directed Greybox Fuzzing (DGF) is a target-oriented fuzzing technique that can reproduce or discover software vulnerabilities. The goal is commonly achieved through two phases: static analysis which obtains program structural information beforehand, and dynamic execution that guides fuzzing towards target sites. However, existing DGF methods still incur heavyweight and incomplete issues. The former comes from extra efforts on identifying and approaching the target sites, while the latter refers to the incompleteness of testing on the target sites due to indirect calls or insufficient paths that recent DGF can cover. In this paper, we propose a Predecessor-aware Directed Greybox Fuzzing (PDGF) method and regard DGF as a path-searching problem. PDGF divides a given program into predecessor and non-predecessor areas, and maintains a set of predecessors by lightweight program analysis initially and augmented during the dynamic execution thereafter. Meanwhile, PDGF introduces a novel fitness metric called regional maturity to indicate the coverage rate of predecessors, and contains a simulated annealing-based power scheduling technique together with seed selection and mutation, to cover the predecessor area efficiently and extensively. We evaluate the proposed PDGF on a benchmark that contains 30 real-world program target sites, and conduct extensive comparisons with state-of-the-art DGF tools. Experimental results reveal that PDGF outperforms competitors in terms of Time-To-Exposure, path diversity, and bug finding. Besides, PDGF discovered nine new vulnerabilities, six of which have been assigned CVEs.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [OOPSLA'23] A Cocktail Approach to Practical Call Graph Construction

[[paper]](https://dl.acm.org/doi/pdf/10.1145/3622833)

<details>
  <summary>Click to see the abstract!</summary>
After decades of research, constructing call graphs for modern C-based software remains either imprecise or inefficient when scaling up to the ever-growing complexity. The main culprit is the difficulty of resolving function pointers, as precise pointer analyses are cubic in nature and become exponential when considering calling contexts. This paper takes a practical stance by first conducting a comprehensive empirical study of function pointer manipulations in the wild. By investigating 5355 indirect calls in five popular open-source systems, we conclude that, instead of the past uniform treatments for function pointers, a cocktail approach can be more effective in “squeezing” the number of difficult pointers to a minimum using a potpourri of cheap methods. In particular, we decompose the costs of constructing highly precise call graphs of big code by tailoring several increasingly precise algorithms and synergizing them into a concerted workflow. As a result, many indirect calls can be precisely resolved in an efficient and principled fashion, thereby reducing the final, expensive refinements. This is, in spirit, similar to the well-known cocktail medical therapy.

The results are encouraging — our implemented prototype called Coral can achieve similar precision versus the previous field-, flow-, and context-sensitive Andersen-style call graph construction, yet scale up to millions of lines of code for the first time, to the best of our knowledge. Moreover, by evaluating the produced call graphs through the lens of downstream clients (i.e., use-after-free detection, thin slicing, and directed grey-box fuzzing), the results show that Coral can dramatically improve their effectiveness for better vulnerability hunting, understanding, and reproduction. More excitingly, we found twelve confirmed bugs (six impacted by indirect calls) in popular systems (e.g., MariaDB), spreading across multiple historical versions.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [ICCAD'23] SurgeFuzz: Surge-Aware Directed Fuzzing for CPU Designs

[[paper]](https://www.rsg.ci.i.u-tokyo.ac.jp/members/shioya/pdfs/Sugiyama-ICCAD'23.pdf) [[project]](https://github.com/shioya-lab-public/surgefuzz)

<details>
  <summary>Click to see the abstract!</summary>
Various verification methods have been proposed for bug detection in central processing unit (CPU) designs, yet their effectiveness remains insufficient. We have observed that such CPU bugs often occur in exceptional handling, such as pipeline stalls and flushes. We found that corner cases in such exceptional handling can be effectively verified through situations we term a ’surge’. A surge refers to a situation where events leading to exceptional handling occur frequently over a short period of time. For instance, a surge caused by frequent queue insertions can eventually fill the capacity, triggering exceptional handling such as a pipeline stall. We propose a novel fuzzing method for CPU designs, named SurgeFuzz, that intentionally generates surges. SurgeFuzz mutates input instruction sequences based on annotations to increase the occurrence of surges. This results in a higher density of event occurrences, thereby enabling efficient verification of corner cases in exceptional handling. We evaluated SurgeFuzz on a large processor design and found several unknown hardware bugs that are difficult to find with existing methods.
</details>

--------------------------------------------------------------------------------------------------------------------------
### [APSEC'23] On the Effectiveness of Synthetic Benchmarks for Evaluating Directed Grey-box Fuzzers

[[paper]](https://softsec.kaist.ac.kr/~sangkilc/papers/lee-apsec23.pdf)

<details>
  <summary>Click to see the abstract!</summary>
Directed grey-box fuzzing is difficult to rigorously evaluate for several reasons. First, directed grey-box fuzzers are more prone to overfitting than undirected grey-box fuzzers as they are designed to explore specific paths in the program under test. Furthermore, existing benchmarks are mainly designed for evaluating undirected fuzzers. Hence, they do not provide any information about bug locations, and the difficulty of triggering bugs can substantially vary across different benchmarks. In this paper, we argue that one can address these challenges by automatically generating benchmarks with a bug synthesis technique. Notably, Fuzzle, a state-of-the-art bug synthesis tool, enables generation of arbitrarily many benchmarks, thereby preventing the overfitting problem. It is also well suited for evaluating directed grey-box fuzzers as it provides the exact location of the target bug in the generated benchmark with a guarantee that the bug is lurking deep in the program. With Fuzzle, we systematically evaluate existing state-of-theart directed fuzzers and study their strengths and weaknesses, which would be otherwise difficult to obtain with traditional benchmarks. To our knowledge, this is the first attempt to adopt a bug synthesis technique for evaluating directed fuzzers.
</details>



