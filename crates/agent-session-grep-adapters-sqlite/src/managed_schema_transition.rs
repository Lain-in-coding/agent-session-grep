//! Inert schema and row-commitment definitions for the exact 22/2 -> 23/3 step.
//!
//! This module opens no files or connections and executes no SQL. Its constants
//! do not change ordinary schema admission. A future executor must own the live
//! exclusion, original deadline and one read snapshot before supplying rows.

#[path = "managed_schema_transition_ddl.rs"]
pub mod ddl;

#[path = "managed_schema_transition_rows.rs"]
pub mod rows;
