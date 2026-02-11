<a name = "Pg1"></a>

# **Chapter 1** - Overview & Getting Started with Serverless PII Leakage Detection

## 1.1 Purpose of the Lab
In this lab, you will learn how to build a serverless PII (Personally Identifiable Information) leakage detection pipeline on AWS using Lambda and API Gateway. You'll learn how Large Language Models can inadvertently leak training data, how to probe for such leakage using the ProPILE methodology, and how to deploy an automated, event-driven auditing system on AWS that measures privacy risk at scale.

This module bridges cloud DevOps (serverless architecture, Infrastructure-as-Code, CI/CD-ready pipelines) with active AI security research (PII leakage measurement, differential privacy, OWASP LLM Top 10 threat modeling). The result is a reproducible, cloud-native research pipeline suitable for IEEE-format publication.

## 1.2 Prerequisites
To follow along and get the most out of this lab, you should:

* Know basic AWS concepts (Lambda, API Gateway, IAM, DynamoDB, CloudWatch).

* Be comfortable using a terminal and the AWS CLI.

* Have access to AWS CloudShell (browser-based, no local install needed).

* Understand Python at a beginner-to-intermediate level.

* Basic understanding of what LLMs are and how they generate text.

* Familiarity with JSON and REST APIs.

## 1.3 References to guide lab work
Please use the links below to learn the related information for this lab.

* <a href="https://docs.aws.amazon.com/lambda/latest/dg/welcome.html">*AWS Lambda Developer Guide*</a> - Official docs for building serverless functions on AWS.
* <a href="https://docs.aws.amazon.com/apigateway/latest/developerguide/welcome.html">*Amazon API Gateway Developer Guide*</a> - Create, deploy, and manage REST/HTTP APIs at any scale.
* <a href="https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Introduction.html">*Amazon DynamoDB Developer Guide*</a> - Fully managed NoSQL database for storing probe results.
* <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/WhatIsCloudWatchLogs.html">*Amazon CloudWatch Logs*</a> - Monitor, store, and access log files from Lambda functions.
* <a href="https://arxiv.org/abs/2310.08437">*Cold Start Latency in Serverless Computing: A Systematic Review (Golec et al.)*</a> - Comprehensive survey of cold start solutions in serverless computing.
* <a href="https://papers.nips.cc/paper_files/paper/2023/hash/420678bb4c8251ab30e9dcd3e1fc5514-Abstract-Conference.html">*ProPILE: Probing Privacy Leakage in Large Language Models (NeurIPS 2023)*</a> - The foundational paper for our probing methodology.
* <a href="https://owasp.org/www-project-top-10-for-large-language-model-applications/">*OWASP Top 10 for LLM Applications (2025)*</a> - Industry-standard threat taxonomy for LLM systems.
* <a href="https://www.usenix.org/system/files/sec21-carlini-extracting.pdf">*Extracting Training Data from Large Language Models (Carlini et al., USENIX 2021)*</a> - Seminal paper demonstrating that LLMs can emit verbatim memorized training data.

## 1.4 Overview

In this lab, we'll build a serverless pipeline on AWS that automatically probes LLMs for PII leakage and collects measurable privacy metrics — all deployed as Lambda functions behind API Gateway.

**What is PII Leakage in LLMs?** Large language models are trained on massive web-crawled datasets that may contain sensitive personal information: names, phone numbers, email addresses, physical addresses, affiliations, and family relationships. When prompted strategically, these models can reconstruct and output this memorized PII — a serious privacy threat. This is cataloged as **LLM06: Sensitive Information Disclosure** in the OWASP LLM Top 10.

**What is ProPILE?** ProPILE (Probing Privacy Leakage in Large Language Models) is a NeurIPS 2023 tool that lets data subjects assess whether their own PII is leakable from LLM services. It works by providing M-1 of a person's PII items in a prompt and measuring whether the LLM can reconstruct the Mth item. For example: given a person's name and email, can the model produce their phone number? ProPILE quantifies this with reconstruction likelihood and exact-match metrics.

**What is Serverless / AWS Lambda?** Serverless computing lets you run code without managing servers. AWS Lambda executes your function only when triggered (e.g., by an API call), scales automatically, and charges only for the milliseconds your code runs. API Gateway provides the HTTP endpoint that triggers Lambda.

**Why Serverless for Privacy Auditing?**

* **Scalable**: Automatically probe thousands of PII entries in parallel without provisioning servers.

* **Cost-efficient**: Pay only when probes run — ideal for batch research experiments.

* **Reproducible**: The entire pipeline is defined in code, deployable with a single command.

* **Measurable**: CloudWatch captures Init Duration (cold start) and execution metrics for every invocation — enabling dual research on both LLM privacy and serverless performance.

## 1.5 Conceptual Overview

<p align="center"> <img src="../img/ch1_pipeline_overview.png" width="900px"></p>

<p align="center"> <i> Figure 1.1: High-level architecture of the Serverless PII Leakage Detection Pipeline. On the left, a researcher triggers probes via API Gateway. API Gateway invokes a Lambda function that: (1) reads PII probe templates from an S3 bucket or DynamoDB, (2) crafts ProPILE-style prompts using M-1 PII items, (3) sends the prompt to an LLM API endpoint, (4) receives the generated response, (5) computes reconstruction likelihood and exact-match scores, and (6) stores the results in DynamoDB. CloudWatch captures all invocation logs including Init Duration for cold start analysis. The pipeline can target multiple LLM endpoints (SLM vs. LLM) for comparative research.</i> </p>

<p align="center"> <img src="../img/ch1_propile_concept.png" width="600px"></p>

<p align="center"> <i> Figure 1.2: ProPILE probing concept (adapted from Kim et al., NeurIPS 2023). A data subject provides M PII items (name, email, phone, address, affiliation). ProPILE constructs prompts using M-1 items and asks the LLM to generate the remaining item. The generated response is compared against the true PII using string distance metrics and reconstruction likelihood. If the model produces a close or exact match, this indicates privacy leakage — the LLM has memorized and can reproduce the data subject's personal information.</i> </p>

## 1.6 Research Context: IEEE Transaction Paper Alignment

This module's research component aligns with active publication venues:

**Primary research question:** How effectively can a serverless, cloud-native pipeline automate PII leakage probing across different LLM endpoints, and what measurable differences emerge between model sizes (SLM vs. LLM)?

**IEEE alignment:** This work contributes to IEEE Transactions on Cloud Computing and IEEE CLOUD conference topics including: serverless computing performance, cloud security architectures, and AI privacy measurement. The dual-layer contribution (LLM privacy measurement + serverless infrastructure performance) addresses the intersection of cloud computing and AI safety.

**Key metrics for publication:**

* Reconstruction likelihood: Pr(a_m | A\m) — probability of reconstructing the target PII given other items.
* Exact match rate: proportion of probes that produce verbatim PII strings.
* γ<sub><k</sub>: fraction of data subjects whose PII is revealed within k queries.
* Cold start latency: Init Duration of Lambda functions across runtimes and configurations.
* End-to-end pipeline throughput: probes per minute under various concurrency levels.

## 1.7 Goals/Outcomes
By the end of this lab module, you will be able to:

(i) Understand LLM Privacy Threats & ProPILE Methodology

* Explain what PII leakage is, why it matters, and how ProPILE measures it.
* Distinguish structured PII (phone, email, address) from unstructured PII (affiliation, relationships).
* Map PII leakage to OWASP LLM Top 10 category LLM06.

(ii) Build Serverless Functions on AWS

* Create Lambda functions in Python that craft prompts, call LLM APIs, and parse responses.
* Configure API Gateway as a REST trigger for Lambda.
* Understand the Lambda execution lifecycle: cold start (INIT) → invoke → freeze → warm start.

(iii) Measure and Analyze PII Leakage

* Implement ProPILE's exact-match and reconstruction-likelihood metrics in code.
* Store probe results in DynamoDB with structured schemas for later analysis.
* Compare leakage rates across different prompt templates and association levels.

(iv) Observe Serverless Performance

* Use CloudWatch to capture Init Duration and invocation duration.
* Understand cold start factors: runtime, memory, package size, VPC attachment.
* Collect data suitable for serverless performance analysis.

(v) Apply Security Controls to the Pipeline

* Create least-privilege IAM roles for Lambda execution.
* Apply OWASP-informed input validation to API Gateway requests.
* Implement audit logging for all probe invocations via CloudWatch.

(vi) Prepare for Research Publication

* Structure collected data as a reproducible dataset.
* Understand how the pipeline outputs map to IEEE paper metrics and methodology sections.