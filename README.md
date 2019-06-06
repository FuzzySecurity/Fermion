# Fermion

Fermion is an electron application that wraps [frida-node](https://github.com/frida/frida-node) and [monaco-editor](https://microsoft.github.io/monaco-editor/). It offers a fully integrated environment to prototype, test and refine Frida scripts through a single UI. With the integration of Monaco come all the features you would expect from Visual Studio Code: Linting, IntelliSense, keybindings, etc. In addition, Fermion has a TypeScript language definition for the Frida API so it is easy to write Frida scripts.

What's in a name: A fermion can be an elementary particle, such as the electron, or it can be a composite particle, such as the proton. Fermions include all quarks and leptons, as well as all composite particles made of an odd number of these, such as all baryons and many atoms and nuclei.

## How to get Fermion?

You can run Fermion from source downloading the repo and then issuing the following commands from a command prompt.

```
set npm_config_runtime=electron
set npm_config_target=5.0.0
npm install
```

Once complete you can run Fermion with:

```
npm start
```

You can compile your own release package with "electron-packager" by navigating to the application folder and issuing the following command.

```
electron-packager . --icon assets\img\fermion.ico
```

Alternatively you can get the latest pre-built version for x64 Windows from [releases](https://github.com/FuzzySecurity/Fermion/releases).

## Eye candy

You can sample of Fermion at work below.

![Fermion](Images/Fermion-1.png)

Fermion has auto-complete, linting and Frida API symbol definitions.

![Help](Images/Fermion-2.png)

## Notes

### Call to action

If you integrate Fermion into your work-flow and find it useful I encourage you to make pull requests, submit bug reports and ask for features to improve the application. I'm not exactly a Node developer so I am sure people will find ways optimize and rework some of the components.

### Special thanks

I just want to give a few special thanks!

* A huge thanks to [Ole André V. Ravnås](https://twitter.com/oleavr) for all his work on Frida and having a lot of patience answering my pedestrian questions about Frida, NodeJS and Monaco!
* A shout-out also to [mattahan](https://www.deviantart.com/mattahan). I'm using a Buuf icon for the Windows package of Fermion. I'm sure we have all used some of his icons on NIX over the years.