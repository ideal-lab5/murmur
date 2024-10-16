import clsx from 'clsx';
import Heading from '@theme/Heading';
import styles from './styles.module.css';

const FeatureList = [
  {
    title: 'Keyless',
    Svg: require('@site/static/img/no_key.svg').default,
    description: (
      <>
        Murmur wallets are truly <b>keyless</b> - 
        users are not responsible for storing and securing mnemonics or secret keys. 
        The protocol requires no keystore or key recovery (e.g. threshold signing) for individual wallets.
      </>
    ),
  },
  {
    title: 'Non-Custodial',
    Svg: require('@site/assets/eye-crossed.svg').default,
    description: (
      <>
        Murmur lets you create in-app wallets that are entirely non-custodial and under user control. It lets developers easily
        add web3 capabilities to applications without the burden of key management, enabling seamless account abstraction for users
        without sacrificing decentralization or other core ethos of web3.
      </>
    ),
  },
  {
    title: 'Seamless Cross-Platform Interoperbility',
    Svg: require('@site/assets/x-platform.svg').default,
    description: (
      <>
        Murmur is versatile and can be integrated in various contexts:
        in the browser, in a bot, a standalone client or any other web-enabled context using Javascript or Rust. 
      </>
    ),
  },
];

function Feature({Svg, title, description}) {
  return (
    <div className={clsx('col col--4')}>
      <div className="text--center">
        <Svg className={styles.featureSvg} role="img" />
      </div>
      <div className="text--center padding-horiz--md">
        <Heading as="h3">{title}</Heading>
        <p>{description}</p>
      </div>
    </div>
  );
}

export default function HomepageFeatures() {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}
