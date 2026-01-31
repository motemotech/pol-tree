use crate::attr_val::*;
use std::collections::HashMap;

/// 決定木のノード
#[derive(Debug, Clone)]
pub enum Node {
    /// 内部ノード（分割条件を持つ）
    Internal {
        attribute: String,
        children: HashMap<String, Box<Node>>,
    },
    /// リーフノード（決定結果を持つ）
    Leaf {
        decision: String,
    },
}

/// 決定木
#[derive(Debug, Clone)]
pub struct DecisionTree {
    root: Option<Box<Node>>,
}

impl DecisionTree {
    /// 新しい空の決定木を作成
    pub fn new() -> Self {
        DecisionTree { root: None }
    }

    /// 決定木を構築（ID3アルゴリズムの簡易版）
    pub fn build(&mut self, examples: &[Example], attributes: &[String]) {
        self.root = Some(self.build_tree(examples, attributes));
    }

    /// 再帰的に決定木を構築
    fn build_tree(&self, examples: &[Example], attributes: &[String]) -> Box<Node> {
        // すべての例が同じクラスなら、リーフノードを作成
        if let Some(decision) = self.all_same_class(examples) {
            return Box::new(Node::Leaf { decision });
        }

        // 属性がなければ、多数決でリーフノードを作成
        if attributes.is_empty() {
            let decision = self.majority_class(examples);
            return Box::new(Node::Leaf { decision });
        }

        // 最良の属性を選択
        let best_attr = self.select_best_attribute(examples, attributes);
        
        // 選択された属性で分割
        let mut children = HashMap::new();
        let remaining_attrs: Vec<String> = attributes
            .iter()
            .filter(|&a| a != &best_attr)
            .cloned()
            .collect();

        // 各属性値でサブセットを作成
        let attribute_values = self.get_attribute_values(examples, &best_attr);
        
        for value in attribute_values {
            let subset: Vec<Example> = examples
                .iter()
                .filter(|ex| ex.get_attribute_value(&best_attr) == Some(&value))
                .cloned()
                .collect();

            if subset.is_empty() {
                // サブセットが空なら、多数決でリーフノードを作成
                let decision = self.majority_class(examples);
                children.insert(value, Box::new(Node::Leaf { decision }));
            } else {
                // 再帰的にサブツリーを構築
                children.insert(value, self.build_tree(&subset, &remaining_attrs));
            }
        }

        Box::new(Node::Internal {
            attribute: best_attr,
            children,
        })
    }

    /// すべての例が同じクラスかチェック
    fn all_same_class(&self, examples: &[Example]) -> Option<String> {
        if examples.is_empty() {
            return None;
        }

        let first_class = &examples[0].class;
        if examples.iter().all(|ex| &ex.class == first_class) {
            Some(first_class.clone())
        } else {
            None
        }
    }

    /// 多数決でクラスを決定
    fn majority_class(&self, examples: &[Example]) -> String {
        let mut class_counts: HashMap<String, usize> = HashMap::new();
        
        for ex in examples {
            *class_counts.entry(ex.class.clone()).or_insert(0) += 1;
        }

        class_counts
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(class, _)| class)
            .unwrap_or_else(|| "unknown".to_string())
    }

    /// 最良の属性を選択（情報利得が最大の属性）
    fn select_best_attribute(&self, examples: &[Example], attributes: &[String]) -> String {
        let mut best_attr = attributes[0].clone();
        let mut best_gain = 0.0;

        let base_entropy = self.entropy(examples);

        for attr in attributes {
            let gain = self.information_gain(examples, attr, base_entropy);
            if gain > best_gain {
                best_gain = gain;
                best_attr = attr.clone();
            }
        }

        best_attr
    }

    /// エントロピーを計算
    fn entropy(&self, examples: &[Example]) -> f64 {
        if examples.is_empty() {
            return 0.0;
        }

        let mut class_counts: HashMap<String, usize> = HashMap::new();
        for ex in examples {
            *class_counts.entry(ex.class.clone()).or_insert(0) += 1;
        }

        let total = examples.len() as f64;
        class_counts
            .values()
            .map(|&count| {
                let p = count as f64 / total;
                if p > 0.0 {
                    -p * p.log2()
                } else {
                    0.0
                }
            })
            .sum()
    }

    /// 情報利得を計算
    fn information_gain(&self, examples: &[Example], attribute: &str, base_entropy: f64) -> f64 {
        let attribute_values = self.get_attribute_values(examples, attribute);
        let total = examples.len() as f64;

        let mut weighted_entropy = 0.0;

        for value in attribute_values {
            let subset: Vec<Example> = examples
                .iter()
                .filter(|ex| ex.get_attribute_value(attribute) == Some(&value))
                .cloned()
                .collect();

            if !subset.is_empty() {
                let subset_entropy = self.entropy(&subset);
                let subset_size = subset.len() as f64;
                weighted_entropy += (subset_size / total) * subset_entropy;
            }
        }

        base_entropy - weighted_entropy
    }

    /// 属性の値のリストを取得
    fn get_attribute_values(&self, examples: &[Example], attribute: &str) -> Vec<String> {
        let mut values: Vec<String> = examples
            .iter()
            .filter_map(|ex| ex.get_attribute_value(attribute))
            .cloned()
            .collect();
        values.sort();
        values.dedup();
        values
    }

    /// 予測を実行
    pub fn predict(&self, example: &Example) -> Option<String> {
        self.root.as_ref().map(|root| self.predict_recursive(root, example))
    }

    /// 再帰的に予測を実行
    fn predict_recursive(&self, node: &Node, example: &Example) -> String {
        match node {
            Node::Leaf { decision } => decision.clone(),
            Node::Internal { attribute, children } => {
                if let Some(value) = example.get_attribute_value(attribute) {
                    if let Some(child) = children.get(value) {
                        self.predict_recursive(child, example)
                    } else {
                        // 未知の値の場合は、最初の子ノードを使用
                        children
                            .values()
                            .next()
                            .map(|child| self.predict_recursive(child, example))
                            .unwrap_or_else(|| "unknown".to_string())
                    }
                } else {
                    // 属性が存在しない場合は、多数決
                    let decisions: Vec<String> = children
                        .values()
                        .map(|child| self.predict_recursive(child, example))
                        .collect();
                    
                    let mut counts: HashMap<String, usize> = HashMap::new();
                    for decision in decisions {
                        *counts.entry(decision).or_insert(0) += 1;
                    }
                    
                    counts
                        .into_iter()
                        .max_by_key(|(_, count)| *count)
                        .map(|(decision, _)| decision)
                        .unwrap_or_else(|| "unknown".to_string())
                }
            }
        }
    }

    /// 決定木を表示（デバッグ用）
    pub fn print(&self) {
        if let Some(ref root) = self.root {
            self.print_recursive(root, 0);
        }
    }

    fn print_recursive(&self, node: &Node, depth: usize) {
        let indent = "  ".repeat(depth);
        match node {
            Node::Leaf { decision } => {
                println!("{}Leaf: {}", indent, decision);
            }
            Node::Internal { attribute, children } => {
                println!("{}Attribute: {}", indent, attribute);
                for (value, child) in children {
                    println!("{}  Value: {}", indent, value);
                    self.print_recursive(child, depth + 2);
                }
            }
        }
    }
}

impl Default for DecisionTree {
    fn default() -> Self {
        Self::new()
    }
}

/// 学習用の例（サンプルデータ）
#[derive(Debug, Clone)]
pub struct Example {
    pub attributes: HashMap<String, String>,
    pub class: String,
}

impl Example {
    /// 新しい例を作成
    pub fn new(class: String) -> Self {
        Example {
            attributes: HashMap::new(),
            class,
        }
    }

    /// 属性を追加
    pub fn add_attribute(&mut self, key: String, value: String) {
        self.attributes.insert(key, value);
    }

    /// 属性値を取得
    pub fn get_attribute_value(&self, attribute: &str) -> Option<&String> {
        self.attributes.get(attribute)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decision_tree() {
        // サンプルデータを作成
        let mut examples = Vec::new();
        
        // 例1: 晴れ、暑い、高湿度、弱い風 -> テニスしない
        let mut ex1 = Example::new("no".to_string());
        ex1.add_attribute("outlook".to_string(), "sunny".to_string());
        ex1.add_attribute("temperature".to_string(), "hot".to_string());
        ex1.add_attribute("humidity".to_string(), "high".to_string());
        ex1.add_attribute("wind".to_string(), "weak".to_string());
        examples.push(ex1);

        // 例2: 晴れ、暑い、高湿度、強い風 -> テニスしない
        let mut ex2 = Example::new("no".to_string());
        ex2.add_attribute("outlook".to_string(), "sunny".to_string());
        ex2.add_attribute("temperature".to_string(), "hot".to_string());
        ex2.add_attribute("humidity".to_string(), "high".to_string());
        ex2.add_attribute("wind".to_string(), "strong".to_string());
        examples.push(ex2);

        // 例3: 曇り、暑い、高湿度、弱い風 -> テニスする
        let mut ex3 = Example::new("yes".to_string());
        ex3.add_attribute("outlook".to_string(), "overcast".to_string());
        ex3.add_attribute("temperature".to_string(), "hot".to_string());
        ex3.add_attribute("humidity".to_string(), "high".to_string());
        ex3.add_attribute("wind".to_string(), "weak".to_string());
        examples.push(ex3);

        // 例4: 雨、適度、高湿度、弱い風 -> テニスする
        let mut ex4 = Example::new("yes".to_string());
        ex4.add_attribute("outlook".to_string(), "rain".to_string());
        ex4.add_attribute("temperature".to_string(), "mild".to_string());
        ex4.add_attribute("humidity".to_string(), "high".to_string());
        ex4.add_attribute("wind".to_string(), "weak".to_string());
        examples.push(ex4);

        // 決定木を構築
        let mut tree = DecisionTree::new();
        let attributes = vec![
            "outlook".to_string(),
            "temperature".to_string(),
            "humidity".to_string(),
            "wind".to_string(),
        ];
        tree.build(&examples, &attributes);

        // 予測をテスト
        let mut test_ex = Example::new("unknown".to_string());
        test_ex.add_attribute("outlook".to_string(), "sunny".to_string());
        test_ex.add_attribute("temperature".to_string(), "mild".to_string());
        test_ex.add_attribute("humidity".to_string(), "high".to_string());
        test_ex.add_attribute("wind".to_string(), "weak".to_string());
        
        let prediction = tree.predict(&test_ex);
        println!("Prediction: {:?}", prediction);
        
        // 決定木を表示
        tree.print();
    }
}

