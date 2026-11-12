//! Les fils de Vanguard, créés sans paniquer. `std::thread::spawn` et `Scope::spawn` paniquent quand le système
//! refuse un fil de plus (limite de processus `RLIMIT_NPROC` atteinte, mémoire épuisée, Windows à court de
//! ressources) : Vanguard s'arrêtait d'un coup, et la règle « pas d'`unwrap` » ne voit pas cette panique cachée.
//! Ici, le refus est rendu à l'appelant (`lancer`, `dans`), qui suit son chemin d'échec (« non vérifié », commande
//! pas lancée), ou le travail se fait sur le fil appelant, l'un après l'autre (`lancer_ou_ici`, `dans_ou_ici`) quand
//! il finit de lui-même. Dans les deux cas le mode réduit est dit : une fois à l'écran (sortie d'erreur, jamais la
//! sortie des commandes en `--json`) et au journal des erreurs. `clippy.toml` interdit les deux appels qui paniquent
//! (`disallowed-methods`).

use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{Builder, JoinHandle, Scope, ScopedJoinHandle};

/// Le mode réduit a déjà été dit à l'écran : une fois suffit, un refus vient rarement seul.
static DIT: AtomicBool = AtomicBool::new(false);

/// Le refus du système, dit (écran une fois, journal chaque fois sauf pour le journal lui-même) et rendu en erreur
/// lisible.
fn refuse(nom: &str, e: &std::io::Error, noter: bool) -> std::io::Error {
    let texte = crate::trf!(
        "le système refuse un fil de plus ({nom}) : {e}",
        "the system refuses one more thread ({nom}): {e}"
    );
    if noter {
        crate::journal::erreur(crate::compte_rendu::Contexte::ErreurInterne, &texte);
    }
    if !DIT.swap(true, Ordering::Relaxed) {
        use std::io::Write as _;
        let _ = writeln!(
            std::io::stderr(),
            "{}",
            crate::trf!(
                "⚠ Mode réduit : {texte}. Vanguard continue, plus lentement ou avec moins de vérifications (celles qui manquent sont dites « non vérifié »).",
                "⚠ Reduced mode: {texte}. Vanguard goes on, more slowly or with fewer checks (the missing ones say \"not verified\")."
            )
        );
    }
    std::io::Error::new(e.kind(), texte)
}

/// Un fil nommé, ou le refus du système (dit). À prendre quand le travail ne peut pas se faire sur le fil appelant :
/// lecture en fond, délai, service qui tourne.
pub(crate) fn lancer<F, T>(nom: &str, f: F) -> std::io::Result<JoinHandle<T>>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    fil(nom, f, true)
}

/// `lancer` pour le journal lui-même (la recherche de sa clé) : le refus n'est dit qu'à l'écran. Noté au journal, il
/// rappellerait la recherche en cours (`OnceLock` repris par le même fil : blocage).
#[cfg(any(windows, test))]
pub(crate) fn lancer_hors_journal<F, T>(nom: &str, f: F) -> std::io::Result<JoinHandle<T>>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    fil(nom, f, false)
}

fn fil<F, T>(nom: &str, f: F, noter: bool) -> std::io::Result<JoinHandle<T>>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    #[cfg(test)]
    if REFUSER.get() {
        return Err(refuse(nom, &refus_simule(), noter));
    }
    Builder::new()
        .name(nom.into())
        .spawn(f)
        .map_err(|e| refuse(nom, &e, noter))
}

/// Un fil nommé dans une portée (`std::thread::scope`), ou le refus du système (dit).
pub(crate) fn dans<'scope, 'env, F, T>(
    portee: &'scope Scope<'scope, 'env>,
    nom: &str,
    f: F,
) -> std::io::Result<ScopedJoinHandle<'scope, T>>
where
    F: FnOnce() -> T + Send + 'scope,
    T: Send + 'scope,
{
    #[cfg(test)]
    if REFUSER.get() {
        return Err(refuse(nom, &refus_simule(), true));
    }
    Builder::new()
        .name(nom.into())
        .spawn_scoped(portee, f)
        .map_err(|e| refuse(nom, &e, true))
}

/// Un travail lancé dans un fil, ou déjà fait sur le fil appelant quand le système a refusé le fil. Le fil rend
/// `Option<T>` : sa fermeture est gardée à part pour le repli, et prise une seule fois.
pub(crate) enum Tenu<H, T> {
    Fil(H),
    Fait(std::thread::Result<T>),
}

/// `lancer_ou_ici` : un fil ou un travail fait.
pub(crate) type Fil<T> = Tenu<JoinHandle<Option<T>>, T>;
/// `dans_ou_ici` : un fil d'une portée ou un travail fait.
pub(crate) type FilDans<'scope, T> = Tenu<ScopedJoinHandle<'scope, Option<T>>, T>;

/// Le résultat d'un fil qui n'aurait pas trouvé sa fermeture : n'arrive pas (seul le fil la prend quand il existe).
fn sans_travail<T>(r: Option<T>) -> std::thread::Result<T> {
    r.ok_or_else(|| -> Box<dyn std::any::Any + Send> { Box::new("fil sans travail") })
}

impl<T> Fil<T> {
    /// Le résultat, comme `JoinHandle::join`.
    pub(crate) fn join(self) -> std::thread::Result<T> {
        match self {
            Tenu::Fil(fil) => fil.join().and_then(sans_travail),
            Tenu::Fait(r) => r,
        }
    }
}

impl<T> FilDans<'_, T> {
    /// Le résultat, comme `ScopedJoinHandle::join`.
    pub(crate) fn join(self) -> std::thread::Result<T> {
        match self {
            Tenu::Fil(fil) => fil.join().and_then(sans_travail),
            Tenu::Fait(r) => r,
        }
    }
}

/// Un travail qui finit de lui-même (sonde à délai propre, calcul) : dans un fil, ou sur le fil appelant si le système
/// refuse le fil (mode réduit dit). Une panique du travail fait ici est rendue par `join`, comme celle d'un fil.
/// Jamais pour un travail qui attend le fil appelant (canal borné, verrou tenu). Pour borner une durée, seulement si
/// le travail a son propre délai (connexion, résolveur du système) : le repli est plus lent, jamais sans fin.
pub(crate) fn lancer_ou_ici<F, T>(nom: &str, f: F) -> Fil<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    // Builder::spawn perd la fermeture avec l'erreur : elle est gardée à part pour le repli.
    let place = std::sync::Arc::new(std::sync::Mutex::new(Some(f)));
    let dans_le_fil = std::sync::Arc::clone(&place);
    match lancer(nom, move || prendre(&dans_le_fil).map(|f| f())) {
        Ok(fil) => Tenu::Fil(fil),
        Err(_) => Tenu::Fait(ici(prendre(&place))),
    }
}

/// `lancer_ou_ici` dans une portée.
pub(crate) fn dans_ou_ici<'scope, 'env, F, T>(
    portee: &'scope Scope<'scope, 'env>,
    nom: &str,
    f: F,
) -> FilDans<'scope, T>
where
    F: FnOnce() -> T + Send + 'scope,
    T: Send + 'scope,
{
    let place = std::sync::Arc::new(std::sync::Mutex::new(Some(f)));
    let dans_le_fil = std::sync::Arc::clone(&place);
    match dans(portee, nom, move || prendre(&dans_le_fil).map(|f| f())) {
        Ok(fil) => Tenu::Fil(fil),
        Err(_) => Tenu::Fait(ici(prendre(&place))),
    }
}

/// La fermeture gardée, prise une seule fois (par le fil, ou par le repli).
fn prendre<F>(place: &std::sync::Mutex<Option<F>>) -> Option<F> {
    place.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take()
}

/// Le travail fait sur le fil appelant, sa panique rattrapée comme celle d'un fil.
fn ici<F, T>(f: Option<F>) -> std::thread::Result<T>
where
    F: FnOnce() -> T,
{
    sans_travail(f).and_then(|f| crate::journal::rattraper(std::panic::AssertUnwindSafe(f)))
}

#[cfg(test)]
thread_local! {
    /// Le système refuse un fil : l'essai le simule (`refuser_les_fils`), pour jouer le repli sans épuiser la machine.
    static REFUSER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Le refus que rend Linux quand `RLIMIT_NPROC` est atteinte (EAGAIN).
#[cfg(test)]
fn refus_simule() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::WouldBlock,
        "Resource temporarily unavailable (essai)",
    )
}

/// Pendant `f`, ce fil se voit refuser chaque nouveau fil, comme sous une limite de processus atteinte.
#[cfg(test)]
pub(crate) fn refuser_les_fils<R>(f: impl FnOnce() -> R) -> R {
    REFUSER.set(true);
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    REFUSER.set(false);
    r.unwrap_or_else(|p| std::panic::resume_unwind(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Un fil refusé : `lancer` et `dans` rendent l'erreur, nommée ; `lancer_ou_ici` et `dans_ou_ici` font le travail
    /// ici, sa panique rendue par `join` comme celle d'un fil. Rien ne panique.
    #[test]
    fn fil_refuse_mode_reduit() {
        refuser_les_fils(|| {
            let e = lancer("essai-refus", || 1).err().unwrap();
            assert!(e.to_string().contains("essai-refus"), "{e}");
            assert!(lancer_hors_journal("essai-journal", || 1).is_err());
            assert_eq!(lancer_ou_ici("essai-ici", || 2).join().unwrap(), 2);
            assert!(
                lancer_ou_ici("essai-panique", || -> u8 { panic!("essai") })
                    .join()
                    .is_err()
            );
            std::thread::scope(|s| {
                assert!(dans(s, "essai-portee", || 1).is_err());
                let a = dans_ou_ici(s, "essai-a", || 40);
                let b = dans_ou_ici(s, "essai-b", || 2);
                assert_eq!(a.join().unwrap() + b.join().unwrap(), 42);
            });
        });
        // Hors du refus : de vrais fils.
        assert_eq!(lancer("essai-vrai", || 5).unwrap().join().unwrap(), 5);
        assert!(matches!(lancer_ou_ici("essai-vrai", || 6), Tenu::Fil(_)));
        std::thread::scope(|s| assert_eq!(dans_ou_ici(s, "essai-vrai", || 7).join().unwrap(), 7));
    }
}
