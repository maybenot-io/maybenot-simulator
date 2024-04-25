use criterion::{black_box, criterion_group, criterion_main, Criterion};
use enum_map::enum_map;
use maybenot::dist::{Dist, DistType};
use maybenot::event::Event;
use maybenot::state::{State, Trans};
use rand_core::RngCore;
use rand_xoshiro::rand_core::SeedableRng;
use rand_xoshiro::Xoshiro256StarStar;

pub fn dist_rng_source_benchmarks(c: &mut Criterion) {
    let n = 1000;
    c.bench_function("11 distributions 1000 samples, thread_rng()", |b| {
        let rng = &mut rand::thread_rng();
        b.iter(|| {
            sample_uniform(rng, black_box(n));
            sample_normal(rng, black_box(n));
            sample_skew_normal(rng, black_box(n));
            sample_log_normal(rng, black_box(n));
            sample_binomial(rng, black_box(n));
            sample_geometric(rng, black_box(n));
            sample_pareto(rng, black_box(n));
            sample_poisson(rng, black_box(n));
            sample_weibull(rng, black_box(n));
            sample_gamma(rng, black_box(n));
            sample_beta(rng, black_box(n));
        })
    });
    c.bench_function("11 distributions 1000 samples, Xoshiro256StarStar", |b| {
        let rng = &mut Xoshiro256StarStar::seed_from_u64(0);
        b.iter(|| {
            sample_uniform(rng, black_box(n));
            sample_normal(rng, black_box(n));
            sample_skew_normal(rng, black_box(n));
            sample_log_normal(rng, black_box(n));
            sample_binomial(rng, black_box(n));
            sample_geometric(rng, black_box(n));
            sample_pareto(rng, black_box(n));
            sample_poisson(rng, black_box(n));
            sample_weibull(rng, black_box(n));
            sample_gamma(rng, black_box(n));
            sample_beta(rng, black_box(n));
        })
    });
}

pub fn transition_rng_source_benchmarks(c: &mut Criterion) {
    let n = 1000;

    // create a state with several transition probabilities
    let state = State::new(enum_map! {
        Event::TunnelSent => vec![
            Trans(0, 0.1),
            Trans(1, 0.1),
            Trans(2, 0.1),
            Trans(3, 0.1),
            Trans(4, 0.1),
            Trans(5, 0.1),
            Trans(6, 0.1),
            Trans(7, 0.1),
            Trans(8, 0.1),
            Trans(9, 0.1),
        ],
    _ => vec![],
    });

    c.bench_function("1000 state transitions, thread_rng()", |b| {
        let rng = &mut rand::thread_rng();
        b.iter(|| {
            sample_state(&state, rng, black_box(n));
        })
    });
    c.bench_function("1000 state transitions, Xoshiro256StarStar", |b| {
        let rng = &mut Xoshiro256StarStar::seed_from_u64(0);
        b.iter(|| {
            sample_state(&state, rng, black_box(n));
        })
    });
}

criterion_group!(rng, dist_rng_source_benchmarks, transition_rng_source_benchmarks);
criterion_main!(rng);

fn sample_state<R: RngCore>(s: &State, rng: &mut R, n: usize) {
    for _ in 0..n {
        s.sample_state(Event::TunnelSent, rng);
    }
}

fn sample_uniform<R: RngCore>(rng: &mut R, n: usize) {
    let d = Dist {
        dist: DistType::Uniform {
            low: 0.0,
            high: 0.0,
        },
        start: 20.0 * 1000.0,
        max: 0.0,
    };

    for _ in 0..n {
        d.sample(rng);
    }
}

fn sample_normal<R: RngCore>(rng: &mut R, n: usize) {
    let d = Dist {
        dist: DistType::Normal {
            mean: 10.0,
            stdev: 20.0,
        },
        start: 20.0 * 1000.0,
        max: 0.0,
    };

    for _ in 0..n {
        d.sample(rng);
    }
}

fn sample_skew_normal<R: RngCore>(rng: &mut R, n: usize) {
    let d = Dist {
        dist: DistType::SkewNormal {
            location: 10.0,
            scale: 20.0,
            shape: 0.5,
        },
        start: 20.0 * 1000.0,
        max: 0.0,
    };

    for _ in 0..n {
        d.sample(rng);
    }
}

fn sample_log_normal<R: RngCore>(rng: &mut R, n: usize) {
    let d = Dist {
        dist: DistType::LogNormal {
            mu: 10.0,
            sigma: 20.0,
        },
        start: 20.0 * 1000.0,
        max: 0.0,
    };

    for _ in 0..n {
        d.sample(rng);
    }
}

fn sample_binomial<R: RngCore>(rng: &mut R, n: usize) {
    let d = Dist {
        dist: DistType::Binomial {
            trials: 10,
            probability: 0.5,
        },
        start: 20.0 * 1000.0,
        max: 0.0,
    };

    for _ in 0..n {
        d.sample(rng);
    }
}

fn sample_geometric<R: RngCore>(rng: &mut R, n: usize) {
    let d = Dist {
        dist: DistType::Geometric { probability: 0.5 },
        start: 20.0 * 1000.0,
        max: 0.0,
    };

    for _ in 0..n {
        d.sample(rng);
    }
}

fn sample_pareto<R: RngCore>(rng: &mut R, n: usize) {
    let d = Dist {
        dist: DistType::Pareto {
            shape: 2.0,
            scale: 1.0,
        },
        start: 20.0 * 1000.0,
        max: 0.0,
    };

    for _ in 0..n {
        d.sample(rng);
    }
}

fn sample_poisson<R: RngCore>(rng: &mut R, n: usize) {
    let d = Dist {
        dist: DistType::Poisson { lambda: 2.0 },
        start: 20.0 * 1000.0,
        max: 0.0,
    };

    for _ in 0..n {
        d.sample(rng);
    }
}

fn sample_weibull<R: RngCore>(rng: &mut R, n: usize) {
    let d = Dist {
        dist: DistType::Weibull {
            shape: 2.0,
            scale: 1.0,
        },
        start: 20.0 * 1000.0,
        max: 0.0,
    };

    for _ in 0..n {
        d.sample(rng);
    }
}

fn sample_gamma<R: RngCore>(rng: &mut R, n: usize) {
    let d = Dist {
        dist: DistType::Gamma {
            shape: 2.0,
            scale: 1.0,
        },
        start: 20.0 * 1000.0,
        max: 0.0,
    };

    for _ in 0..n {
        d.sample(rng);
    }
}

fn sample_beta<R: RngCore>(rng: &mut R, n: usize) {
    let d = Dist {
        dist: DistType::Beta {
            alpha: 2.0,
            beta: 1.0,
        },
        start: 20.0 * 1000.0,
        max: 0.0,
    };

    for _ in 0..n {
        d.sample(rng);
    }
}
