// use std::{borrow::Cow, collections::HashMap, lazy::SyncLazy};

// use async_graphql::{EnumType, InputType, OutputType, Type, resolver_utils::EnumItem};
// use inflector::Inflector;

// use crate::config::CONFIG;

// static PROVIDER_NAMES: SyncLazy<HashMap<String, String>> = SyncLazy::new(|| {
//     CONFIG
//         .providers
//         .keys()
//         .map(|id| (id.to_owned(), id.to_screaming_snake_case()))
//         .collect()
// });

// static PROVIDER_ITEMS: SyncLazy<Vec<EnumItem<Provider>>> = SyncLazy::new(|| {
//     PROVIDER_NAMES
//         .iter()
//         .map(|(id, name)| EnumItem {
//             name: &name,
//             value: Provider { id: &id },
//         })
//         .collect()
// });

// static PROVIDERS: SyncLazy<HashMap<String, Provider>> = SyncLazy::new(|| {
//     PROVIDER_NAMES
//         .keys()
//         .map(|id| (id.to_owned(), Provider { id: &id }))
//         .collect()
// });

// #[derive(Copy, Clone, PartialEq, Eq)]
// pub struct Provider {
//     id: &'static str,
// }

// impl Provider {
//     pub fn new(id: &str) -> Option<Self> {
//         PROVIDERS.get(id).map(Self::to_owned)
//     }
//     pub fn as_str(&self) -> &'static str {
//         self.id
//     }
// }

// impl Type for Provider {
//     fn type_name() -> Cow<'static, str> {
//         "Provider".into()
//     }

//     fn create_type_info(registry: &mut async_graphql::registry::Registry) -> String {
//         registry.create_type::<Self, _>(|_| async_graphql::registry::MetaType::Enum {
//             name: "Provider".into(),
//             description: None,
//             enum_values: {
//                 let mut enum_items = async_graphql::indexmap::IndexMap::new();

//                 PROVIDER_ITEMS.iter().for_each(|item| {
//                     enum_items.insert(item.name, async_graphql::registry::MetaEnumValue {
//                         name: item.name,
//                         description: None,
//                         deprecation: async_graphql::registry::Deprecation::NoDeprecated,
//                         visible: None,
//                     });
//                 });

//                 enum_items
//             },
//             visible: None,
//         })
//     }
// }

// #[async_trait::async_trait]
// impl OutputType for Provider {
//     async fn resolve(
//         &self,
//         _: &async_graphql::ContextSelectionSet<'_>,
//         _field: &async_graphql::Positioned<async_graphql::parser::types::Field>,
//     ) -> async_graphql::ServerResult<async_graphql::Value> {
//         Ok(async_graphql::resolver_utils::enum_value(*self))
//     }
// }

// impl InputType for Provider {
//     fn parse(value: ::std::option::Option<async_graphql::Value>) -> async_graphql::InputValueResult<Self> {
//         async_graphql::resolver_utils::parse_enum(value.unwrap_or_default())
//     }

//     fn to_value(&self) -> async_graphql::Value {
//         async_graphql::resolver_utils::enum_value(*self)
//     }
// }

// impl EnumType for Provider {
//     fn items() -> &'static [EnumItem<Self>] {
//         &PROVIDER_ITEMS
//     }
// }
