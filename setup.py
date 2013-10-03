from setuptools import setup, find_packages

version = '0.1'

setup(name='dontpanic',
      version=version,
      description="Script that checks all uncommented domains"
      " in a nginx or apache config directory.",
      long_description="""\
""",
      # TODO
      classifiers=[], # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
      keywords='',
      author='Andraz Brodnik',
      author_email='brodul@brodul.org',
      url='',
      license='MIT',
      packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
      include_package_data=True,
      zip_safe=False,
      install_requires=[
          "dnspython",
      ],
      entry_points="""
      # -*- Entry points: -*-
      """,
      )
