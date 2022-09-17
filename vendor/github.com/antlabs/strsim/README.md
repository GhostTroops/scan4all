## strsim
strsim是golang实现的字符串相识度库，后端集成多种算法，主要解决现有相似度库不能很好的处理中文

[![Go](https://github.com/antlabs/strsim/workflows/Go/badge.svg)](https://github.com/antlabs/strsim/actions)
[![codecov](https://codecov.io/gh/antlabs/strsim/branch/master/graph/badge.svg)](https://codecov.io/gh/antlabs/strsim)

## 构架
![strsim.png](https://github.com/guonaihong/images/blob/master/strsim/strsim.png?raw=true)



## 使用方式

```go
go get -u github.com/antlabs/strsim
```





## 功能
* 可以忽略空白字符
* 可以大小写
    ### 多种算法支持
    * 莱文斯坦-编辑距离(Levenshtein)
    * Hamming
    * Dice's coefficient
    * Jaro 
    * JaroWinkler 
    * Cosine 
    * Simhash

## 内容
- [比较两个字符串相识度](#比较两个字符串相识度)
- [从字符串数组里面找到相似度最高的字符串](#从数组里找到相似度最高的字符串)
- [从字符串数组里面找到相似度最高的字符串-带下标](#从数组里找到相似度最高的字符串-带下标)
- [选择不同算法](##选择不同算法)
    - [莱文斯坦-编辑距离(Levenshtein)](#莱文斯坦-编辑距离(Levenshtein))
    - [选择Dice's coefficient](#选择Dice's-coefficient)
    - [选择jaro](#选择jaro)
    - [选择Hamming](#选择Hamming)
    - [选择JaroWinkler](#选择JaroWinkler)
    - [选择Cosine](#选择Cosine)
    - [选择Simhash](#选择Simhash)
## 比较两个字符串相识度
```go
strsim.Compare("中国人", "中")
// -> 0.333333
```

## 从数组里找到相似度最高的字符串
```go
strsim.FindBestMatchOne("海刘", []string{"白日依山尽", "黄河入海流", "欲穷千里目", "更上一层楼"})
```
## 从数组里找到相似度最高的字符串-带下标
```go
strsim.FindBestMatch("海刘", []string{"白日依山尽", "黄河入海流", "欲穷千里目", "更上一层楼"})
```

## 选择不同算法
### 莱文斯坦-编辑距离(Levenshtein)
```go
strsim.Compare("abc", "ab")
// -> 0.6666666666666667
```
### 选择Dice's coefficient
```go
strsim.Compare("abc", "ab", strsim.DiceCoefficient())
//-> 0.6666666666666666
```
### 选择jaro
```go
strsim.Compare("abc", "ab", strsim.Jaro())
```
### 选择JaroWinkler 

```go
strsim.Compare("abc", "ab", strsim.JaroWinkler())
```

### 选择Hamming
```go
strsim.Compare("abc", "ab", strsim.Hamming())
```

### 选择Cosine

```go
strsim.Compare("abc", "ab", strsim.Cosine())
```

### 选择Simhash

```go
strsim.Compare("abc", "ab", strsim.Simhash())
```

