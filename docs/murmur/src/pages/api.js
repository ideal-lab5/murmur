import clsx from 'clsx';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';
import HomepageFeatures from '@site/src/components/HomepageFeatures';

export default function Api() {
  return (
    <Layout
      title="murmur-api docs"
      description="Murmur API documentation">
      <main>
        {/* <span>
          curl --cookie-jar cookies -H "Content-Type: application/json" -d '{"username": "test", "password": "test"}' http://localhost:8000/authenticate
        </span> */}
      </main>
    </Layout>
  );
}
