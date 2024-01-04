use std::fmt::{self, Debug};

#[derive(Clone)]
pub enum Tree {
    Zero,
    One,
    Unnamed,
    Name(String),
    Add(Box<Tree>, Box<Tree>),
    Sub(Box<Tree>, Box<Tree>),
    Mul(Box<Tree>, Box<Tree>),
    Inv(Box<Tree>),
    Neg(Box<Tree>),
}

impl Debug for Tree {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Tree::Zero => f.write_str("0"),
            Tree::One => f.write_str("1"),
            Tree::Unnamed => f.write_str("?"),
            Tree::Name(s) => f.write_str(s),
            Tree::Add(l, r) => write!(f, "({l:?} + {r:?})"),
            Tree::Sub(l, r) => write!(f, "({l:?} - {r:?})"),
            Tree::Mul(l, r) => write!(f, "{l:?} * {r:?}"),
            Tree::Inv(x) => write!(f, "{x:?}⁻¹"),
            Tree::Neg(x) => write!(f, "-{x:?}"),
        }
    }
}
