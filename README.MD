# Readme

## 参考材料

`./VANDALIR.pdf` `Apposcopy- Semantics-Based Detection of Android Malware through Static Analysis`是我们要参考的论文，前者是对系统恶意软件的检测(LLVM-IR + Datalog), 后者是Android恶意软件的检测(static taint analysis&ICCG + Datalog).

`./vandalir` 是VANDALIR论文的代码

`./apposcopy` 是Apposcopy论文的代码

`./The Evolution of Android Malware and Android Analysis Techniques.pdf`是安卓恶意软件的综述，写的挺好的，可以看一下

`./Android综述.pdf`是中文综述

`./Datalog Programs and Their Stable Models.pdf`，`Using Datalog for Fast and Easy Program Analysis.pdf`和`978-3-642-24206-9.pdf`是关于datalog的文章

## 数据集

`Malgenome`   出处：Dissecting Android Malware: Characterization and Evolution

在这个数据集文件下：
- `malware-genome.zip`是原数据集文件
- `family/`是根据malware family 进行分类的数据。每个文件夹名是family name，其下文件是所属该malware family的malware samples
- `malgenome-215-dataset-1260malware-2539-benign.csv`是这个数据集原始分析文件
- `dataset-features-categories.csv`是之前项目在这个数据集中提取到的恶意行为特征（部分）。`malgenome.p`和`df_malgenome.p`分别是根据上个特征文件，所做的数据集特征矩阵（数据中samples*特征）   <u>这几个文件与project关联不大</u>

## repository

我在github上新建了个代码库：
```
https://github.com/Shoubi007/Formalizing-Malicious-Behaviors.git
```
通过pull request上传代码

## project想法

1. 对Android数据集使用FlowDroid(https://github.com/secure-software-engineering/FlowDroid.git)或者DidFail(https://www.wklieber.com/didfail/)得到组件间的数据流分析。
2. 构建datalog谓词（参考论文）
3. 得到每个Android malware的Datalog文件，表示出该malware的恶意行为。
4. 在混淆后的数据上进行测试。

