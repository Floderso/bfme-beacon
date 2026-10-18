//! The AIO's resolution (spec 10 §3 step 5, R10-2) from a selected package to the
//! expected file set of a [`GameConfig`], and the host's catalog of selectable
//! configurations.
//!
//! Layers, highest priority first: L1 the selected enhancement (if one was
//! selected), L2 the package, L3 its type-0 dependencies (recursively, `guid:version`
//! pins honoured, otherwise the version in the library), L4 the base game
//! `original-BFME1`. Per layer every file is skipped if its name is one the AIO
//! ignores, if it is a `.wps` script, or if its language list neither is
//! `ALL`/empty nor contains the chosen language. Destination = folder (game, or
//! the `-mod` folder for a type-1 package) + lower-cased name; **the first layer
//! that names a destination wins**, so a package can replace or blank out a
//! lower layer's file.

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::fmt;
use std::sync::Arc;

use beacon_proto::control::{ConfigError, ConfigFile, FileDir, GameConfig, PackageRef, MAX_CONFIG_LAYERS};
use serde::Serialize;

use super::library::{PackageSet, PackageSource};
use super::manifest::{Package, PackageKind};
use super::BASE_GUID;

/// File names the AIO never installs (`ConfigUtils.IgnoredGameFiles`, spec 10
/// §3; its intro-movie names do not occur in any BFME1 manifest seen and are not
/// listed here).
pub const IGNORED_FILE_NAMES: &[&str] = &["_zzlotr.big", "mod.txt", "timer_frame.png"];

/// Most packages followed while resolving dependencies.
const MAX_RESOLVED: usize = MAX_CONFIG_LAYERS;

/// Why a configuration cannot be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// The selected package is not known.
    UnknownPackage(String),
    /// A dependency is not in the library.
    MissingDependency {
        /// The dependency (`guid` or `guid:version`).
        dependency: String,
        /// The package that needs it.
        of: String,
    },
    /// The base game's manifest (`original-BFME1`) is not in the library.
    MissingBase,
    /// Not a BFME1 package.
    WrongGame,
    /// A type Beacon does not support (map packs, snapshots).
    Unsupported(PackageKind),
    /// An enhancement without a patch or mod to build on.
    NoBase(String),
    /// Too many packages.
    TooManyPackages,
    /// The language code is malformed.
    BadLanguage(String),
    /// The result breaks a configuration rule.
    Config(ConfigError),
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownPackage(k) => write!(f, "unknown package {k}"),
            Self::MissingDependency { dependency, of } => {
                write!(f, "{of} needs {dependency}, which is not in the BFME Workshop library")
            }
            Self::MissingBase => f.write_str("the base game's manifest (original-BFME1) is not in the BFME Workshop library"),
            Self::WrongGame => f.write_str("not a BFME1 package"),
            Self::Unsupported(k) => write!(f, "packages of type {k:?} are not supported"),
            Self::NoBase(name) => write!(f, "{name} does not name a patch or mod to build on"),
            Self::TooManyPackages => f.write_str("too many packages"),
            Self::BadLanguage(l) => write!(f, "invalid language {l:?}"),
            Self::Config(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ResolveError {}

/// The packages of a configuration, highest priority first.
#[derive(Debug, Clone)]
pub struct Layers {
    /// The selected package (an enhancement, a patch or a mod).
    pub selected: Arc<Package>,
    /// Every layer, highest priority first (ends with the base game).
    pub layers: Vec<Arc<Package>>,
}

fn dep_label(guid: &str, version: Option<&str>) -> String {
    match version {
        Some(v) => format!("{guid}:{v}"),
        None => guid.to_owned(),
    }
}

/// The layers of a selection: enhancement, package, type-0 dependencies, base.
pub fn layers(set: &PackageSet, guid: &str, version: Option<&str>) -> Result<Layers, ResolveError> {
    let selected = set
        .get(guid, version)
        .ok_or_else(|| ResolveError::UnknownPackage(dep_label(guid, version)))?;
    if selected.game != 0 {
        return Err(ResolveError::WrongGame);
    }
    let (enhancement, main) = match selected.kind {
        PackageKind::Patch | PackageKind::Mod => (None, Arc::clone(&selected)),
        PackageKind::Enhancement => {
            // An enhancement lists the patch or mod it builds on.
            let base = selected
                .dependencies
                .iter()
                .find_map(|d| {
                    set.get(&d.guid, d.version.as_deref())
                        .filter(|p| matches!(p.kind, PackageKind::Patch | PackageKind::Mod))
                })
                .ok_or_else(|| {
                    // Name the dependency the library lacks, if that is the reason.
                    match selected
                        .dependencies
                        .iter()
                        .find(|d| set.get(&d.guid, d.version.as_deref()).is_none())
                    {
                        Some(d) => ResolveError::MissingDependency {
                            dependency: d.to_string(),
                            of: selected.name.clone(),
                        },
                        None => ResolveError::NoBase(selected.name.clone()),
                    }
                })?;
            (Some(Arc::clone(&selected)), base)
        }
        other => return Err(ResolveError::Unsupported(other)),
    };
    let mut out: Vec<Arc<Package>> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    if let Some(e) = enhancement {
        seen.insert(e.guid.clone());
        out.push(e);
    }
    seen.insert(main.guid.clone());
    out.push(Arc::clone(&main));
    // Dependencies breadth-first: explicit ones in their order, then theirs.
    let mut queue: VecDeque<(Arc<Package>, usize)> = VecDeque::from([(Arc::clone(&main), 0)]);
    while let Some((pkg, depth)) = queue.pop_front() {
        for dep in &pkg.dependencies {
            if seen.contains(&dep.guid) || dep.guid == BASE_GUID {
                continue;
            }
            let found = set
                .get(&dep.guid, dep.version.as_deref())
                .ok_or_else(|| ResolveError::MissingDependency {
                    dependency: dep.to_string(),
                    of: pkg.name.clone(),
                })?;
            seen.insert(dep.guid.clone());
            if depth >= MAX_RESOLVED || out.len() >= MAX_RESOLVED {
                return Err(ResolveError::TooManyPackages);
            }
            if found.kind == PackageKind::Patch {
                out.push(Arc::clone(&found));
            }
            queue.push_back((found, depth + 1));
        }
    }
    let base = set.get(BASE_GUID, None).ok_or(ResolveError::MissingBase)?;
    if !out.iter().any(|p| p.guid == BASE_GUID) {
        out.push(base);
    }
    if out.len() > MAX_CONFIG_LAYERS {
        return Err(ResolveError::TooManyPackages);
    }
    Ok(Layers { selected, layers: out })
}

/// The language codes the layers offer (every code of a language-specific file).
pub fn languages(layers: &Layers) -> Vec<String> {
    let mut codes = BTreeSet::new();
    for p in &layers.layers {
        for f in &p.files {
            if let super::manifest::FileLanguages::Only(list) = &f.languages {
                codes.extend(list.iter().cloned());
            }
        }
    }
    codes.into_iter().collect()
}

/// The default language: the host's game language if offered, else `EN` if
/// offered, else the first offered, else `EN`.
pub fn default_language(offered: &[String], game_language: Option<&str>) -> String {
    game_language
        .filter(|g| offered.iter().any(|o| o == g))
        .map(str::to_owned)
        .or_else(|| offered.iter().find(|o| *o == "EN").cloned())
        .or_else(|| offered.first().cloned())
        .unwrap_or_else(|| "EN".to_owned())
}

fn file_name(path: &str) -> &str {
    path.rsplit('\\').next().unwrap_or(path)
}

/// Builds the configuration: the AIO's file list for `language`. `known_size`
/// fills sizes the manifests leave at 0 (from the host's store).
pub fn build_config(
    layers: &Layers,
    language: &str,
    known_size: &dyn Fn(&str) -> Option<u64>,
) -> Result<GameConfig, ResolveError> {
    if !beacon_proto::control::is_valid_language(language) {
        return Err(ResolveError::BadLanguage(language.to_owned()));
    }
    let mut files: BTreeMap<(FileDir, String), ConfigFile> = BTreeMap::new();
    for p in &layers.layers {
        let dir = if p.kind == PackageKind::Mod { FileDir::Mod } else { FileDir::Game };
        for f in &p.files {
            let name = file_name(&f.path);
            if IGNORED_FILE_NAMES.contains(&name) || name.ends_with(".wps") || !f.languages.includes(language) {
                continue;
            }
            files.entry((dir, f.path.clone())).or_insert_with(|| ConfigFile {
                path: f.path.clone(),
                md5: f.md5.clone(),
                size: if f.size > 0 { f.size } else { known_size(&f.md5).unwrap_or(0) },
                dir,
            });
        }
    }
    let sel = &layers.selected;
    GameConfig {
        id: String::new(),
        guid: sel.guid.clone(),
        version: sel.version.clone(),
        name: sel.name.clone(),
        author: sel.author.clone(),
        language: language.to_owned(),
        layers: layers
            .layers
            .iter()
            .map(|p| PackageRef {
                guid: p.guid.clone(),
                version: p.version.clone(),
                name: p.name.clone(),
                author: p.author.clone(),
                kind: p.kind.number(),
            })
            .collect(),
        files: files.into_values().collect(),
    }
    .finalize()
    .map_err(ResolveError::Config)
}

/// One selectable configuration for the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CatalogEntry {
    /// `guid@version` (what the UI sends back).
    pub key: String,
    /// Guid.
    pub guid: String,
    /// Version.
    pub version: String,
    /// Name.
    pub name: String,
    /// Author.
    pub author: String,
    /// Workshop type (0 patch, 1 mod, 2 enhancement).
    pub kind: u8,
    /// The other packages it brings along ("Patch 1.06 1.0.0"), highest first,
    /// without the base game.
    pub with: Vec<String>,
    /// Language variants offered.
    pub languages: Vec<String>,
    /// Preselected language.
    pub default_language: String,
    /// Files of the configuration in the default language.
    pub files: usize,
    /// Known size of those files.
    pub total_size: u64,
    /// The AIO currently has this package active.
    pub active_in_aio: bool,
    /// Where the manifest came from.
    pub source: PackageSource,
    /// Links from the manifest.
    pub social_links: Vec<String>,
    /// Why it cannot be selected (missing dependency, …).
    pub problem: Option<String>,
}

/// Every BFME1 patch, mod and enhancement of the set as a catalog entry, sorted
/// by name (entries that cannot be resolved carry a `problem`).
pub fn catalog(set: &PackageSet, game_language: Option<&str>, known_size: &dyn Fn(&str) -> Option<u64>) -> Vec<CatalogEntry> {
    let mut out: Vec<CatalogEntry> = set
        .iter()
        .filter(|(p, _)| {
            p.game == 0 && matches!(p.kind, PackageKind::Patch | PackageKind::Mod | PackageKind::Enhancement)
        })
        .map(|(p, source)| {
            let mut entry = CatalogEntry {
                key: p.key(),
                guid: p.guid.clone(),
                version: p.version.clone(),
                name: p.name.clone(),
                author: p.author.clone(),
                kind: p.kind.number(),
                with: Vec::new(),
                languages: Vec::new(),
                default_language: "EN".to_owned(),
                files: 0,
                total_size: 0,
                active_in_aio: set.active.as_ref().is_some_and(|(g, v)| *g == p.guid && *v == p.version),
                source,
                social_links: p.social_links.clone(),
                problem: None,
            };
            match layers(set, &p.guid, Some(&p.version)) {
                Ok(l) => {
                    entry.with = l
                        .layers
                        .iter()
                        .filter(|x| x.guid != p.guid && !x.is_base())
                        .map(|x| format!("{} {}", x.name, x.version))
                        .collect();
                    entry.languages = languages(&l);
                    entry.default_language = default_language(&entry.languages, game_language);
                    match build_config(&l, &entry.default_language, known_size) {
                        Ok(c) => {
                            entry.files = c.files.len();
                            entry.total_size = c.total_size();
                        }
                        Err(e) => entry.problem = Some(e.to_string()),
                    }
                }
                Err(e) => entry.problem = Some(e.to_string()),
            }
            entry
        })
        .collect();
    out.sort_by(|a, b| {
        (a.name.to_lowercase(), &a.version).cmp(&(b.name.to_lowercase(), &b.version))
    });
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::mods::library::PackageSource;
    use crate::mods::manifest::parse_manifest;
    use crate::mods::manifest::tests::manifest_json;

    pub(crate) const PATCH: &str = "patch-106";
    pub(crate) const MOD: &str = "mod-lot3a";

    fn md5(c: char) -> String {
        c.to_string().repeat(32)
    }

    /// A synthetic library: base game, a patch, a type-0 "mod" on it, an
    /// enhancement on that, a type-1 mod, a map pack.
    pub(crate) fn sample_set() -> PackageSet {
        let mut set = PackageSet::new();
        let mut add = |json: String| set.insert(parse_manifest(json.as_bytes()).unwrap(), PackageSource::Aio);
        add(manifest_json(
            BASE_GUID,
            "Vanilla (1.03)",
            "1.0.0",
            0,
            &[
                ("lotrbfme.exe", &md5('0'), 16, "ALL"),
                ("asset.dat", &md5('1'), 10, "ALL"),
                ("_aptpatch.big", &md5('2'), 0, "ALL"),
                ("lang\\English.big", &md5('3'), 30, "EN"),
                ("lang\\German.big", &md5('4'), 40, "DE"),
                ("data\\movies\\Intro.vp6", &md5('5'), 50, "ALL"),
                ("mod.txt", &md5('6'), 1, "ALL"),
            ],
            &[],
        ));
        add(manifest_json(
            PATCH,
            "Patch 1.06",
            "1.0.0",
            0,
            &[
                ("_patch106.big", &md5('7'), 70, "ALL"),
                ("asset.dat", &md5('8'), 0, "ALL"),
                ("_germanpatch106.big", &md5('9'), 90, "DE"),
            ],
            &[],
        ));
        add(manifest_json(
            MOD,
            "Legends of the 3rd Age",
            "0.5.2",
            0,
            &[
                ("_zlot3a_data.big", &md5('a'), 100, "ALL"),
                ("asset.dat", &md5('b'), 11, "ALL"),
                ("install.wps", &md5('c'), 1, "ALL"),
            ],
            &[&format!("{PATCH}:1.0.0")],
        ));
        add(manifest_json(
            "enh-ui",
            "Classic UI",
            "1.0.1",
            2,
            &[("_zlot3a_zzui.big", &md5('d'), 5, "ALL"), ("_aptpatch.big", &md5('e'), 0, "ALL")],
            &[MOD],
        ));
        add(manifest_json("mod-t1", "Type One", "1.0.0", 1, &[("t1.big", &md5('f'), 3, "ALL")], &[PATCH]));
        add(manifest_json("maps", "Map Pack", "1.0", 3, &[], &[]));
        add(manifest_json("broken", "Broken", "1.0", 0, &[], &["missing-dep:2.0"]));
        add(manifest_json("enh-orphan", "Orphan", "1.0", 2, &[], &["missing-patch"]));
        set
    }

    fn paths(c: &GameConfig) -> Vec<(FileDir, &str, &str)> {
        c.files.iter().map(|f| (f.dir, f.path.as_str(), f.md5.as_str())).collect()
    }

    #[test]
    fn layers_follow_the_aio() {
        let set = sample_set();
        let l = layers(&set, MOD, None).unwrap();
        let guids: Vec<&str> = l.layers.iter().map(|p| p.guid.as_str()).collect();
        assert_eq!(guids, [MOD, PATCH, BASE_GUID]);
        let c = build_config(&l, "EN", &|_| None).unwrap();
        // First layer wins (LOT3A's asset.dat), ignored names and scripts are
        // skipped, the German file is not installed for EN.
        assert_eq!(
            paths(&c),
            [
                (FileDir::Game, "_aptpatch.big", md5('2').as_str()),
                (FileDir::Game, "_patch106.big", md5('7').as_str()),
                (FileDir::Game, "_zlot3a_data.big", md5('a').as_str()),
                (FileDir::Game, "asset.dat", md5('b').as_str()),
                (FileDir::Game, "data\\movies\\intro.vp6", md5('5').as_str()),
                (FileDir::Game, "lang\\english.big", md5('3').as_str()),
                (FileDir::Game, "lotrbfme.exe", md5('0').as_str()),
            ]
        );
        assert_eq!(c.guid, MOD);
        assert_eq!(c.layers.len(), 3);
        let de = build_config(&l, "DE", &|m| (m == md5('2')).then_some(77)).unwrap();
        assert!(de.files.iter().any(|f| f.path == "lang\\german.big"));
        assert!(de.files.iter().any(|f| f.path == "_germanpatch106.big"));
        assert!(!de.files.iter().any(|f| f.path == "lang\\english.big"));
        assert_eq!(de.files.iter().find(|f| f.path == "_aptpatch.big").unwrap().size, 77, "size from the store");
        assert_ne!(de.id, c.id);
        assert_eq!(languages(&l), ["DE", "EN"]);
    }

    #[test]
    fn enhancements_and_type_one_mods() {
        let set = sample_set();
        let l = layers(&set, "enh-ui", Some("1.0.1")).unwrap();
        let guids: Vec<&str> = l.layers.iter().map(|p| p.guid.as_str()).collect();
        assert_eq!(guids, ["enh-ui", MOD, PATCH, BASE_GUID]);
        let c = build_config(&l, "EN", &|_| None).unwrap();
        assert_eq!(c.name, "Classic UI");
        // The enhancement's empty _aptpatch.big replaces the base's.
        assert_eq!(c.files.iter().find(|f| f.path == "_aptpatch.big").unwrap().md5, md5('e'));
        let t1 = build_config(&layers(&set, "mod-t1", None).unwrap(), "EN", &|_| None).unwrap();
        assert!(t1.has_mod_dir());
        assert_eq!(
            t1.files.iter().filter(|f| f.dir == FileDir::Mod).map(|f| f.path.as_str()).collect::<Vec<_>>(),
            ["t1.big"]
        );
        assert!(t1.files.iter().any(|f| f.dir == FileDir::Game && f.path == "_patch106.big"));
    }

    #[test]
    fn errors() {
        let set = sample_set();
        assert!(matches!(layers(&set, "nope", None), Err(ResolveError::UnknownPackage(_))));
        assert!(matches!(layers(&set, "maps", None), Err(ResolveError::Unsupported(PackageKind::MapPack))));
        assert!(matches!(layers(&set, "broken", None), Err(ResolveError::MissingDependency { .. })));
        assert!(matches!(
            layers(&set, "enh-orphan", None),
            Err(ResolveError::MissingDependency { ref dependency, .. }) if dependency == "missing-patch"
        ));
        let l = layers(&set, MOD, None).unwrap();
        assert!(matches!(build_config(&l, "english", &|_| None), Err(ResolveError::BadLanguage(_))));
        let mut no_base = PackageSet::new();
        no_base.insert(
            parse_manifest(manifest_json("p", "P", "1", 0, &[("a.big", &md5('a'), 1, "ALL")], &[]).as_bytes()).unwrap(),
            PackageSource::Aio,
        );
        assert_eq!(layers(&no_base, "p", None).err(), Some(ResolveError::MissingBase));
    }

    #[test]
    fn catalog_lists_selectable_configurations() {
        let mut set = sample_set();
        set.active = Some((PATCH.into(), "1.0.0".into()));
        let cat = catalog(&set, Some("DE"), &|_| None);
        let names: Vec<&str> = cat.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names,
            ["Broken", "Classic UI", "Legends of the 3rd Age", "Orphan", "Patch 1.06", "Type One", "Vanilla (1.03)"]
        );
        let lot3a = cat.iter().find(|e| e.guid == MOD).unwrap();
        assert_eq!(lot3a.with, ["Patch 1.06 1.0.0"]);
        assert_eq!(lot3a.default_language, "DE");
        assert!(lot3a.problem.is_none());
        assert!(cat.iter().find(|e| e.guid == PATCH).unwrap().active_in_aio);
        assert!(cat.iter().find(|e| e.guid == "broken").unwrap().problem.is_some());
        assert_eq!(default_language(&["DE".into(), "EN".into()], Some("FR")), "EN");
        assert_eq!(default_language(&[], None), "EN");
    }
}
