<!--
*** Thanks for checking out the Best-README-Template. If you have a suggestion
*** that would make this better, please fork the repo and create a pull request
*** or simply open an issue with the tag "enhancement".
*** Thanks again! Now go create something AMAZING! :D
-->



<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
***[![Contributors][contributors-shield]][contributors-url]
***[![Forks][forks-shield]][forks-url]
***[![Stargazers][stars-shield]][stars-url]
***[![Issues][issues-shield]][issues-url]
***[![MIT License][license-shield]][license-url]
***[![LinkedIn][linkedin-shield]][linkedin-url]



<!-- PROJECT LOGO -->
<br />
<p align="center">
  <a href="https://www.mtu.ie/">
    <img src="https://marketing.cit.ie/contentfiles/images/MTU/Logos/MTU-social-Profile-Logo.jpg" alt="Logo" width="280" height="280">
  </a>

  <h3 align="center">Best-README-Template</h3>

  <p align="center">
    An awesome README template to jumpstart your projects!
    <br />
    <a href="https://github.com/othneildrew/Best-README-Template"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/othneildrew/Best-README-Template">View Demo</a>
    ·
    <a href="https://github.com/othneildrew/Best-README-Template/issues">Report Bug</a>
    ·
    <a href="https://github.com/othneildrew/Best-README-Template/issues">Request Feature</a>
  </p>
</p>



<!-- TABLE OF CONTENTS -->
<details open="open">
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgements">Acknowledgements</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project


<p align="center">
<a href="https://www.mtu.ie/">
    <img src="https://shanemccausland.com/wp-content/uploads/2021/08/iot_hawk_logo.png" alt="Logo" >
  </a>
</p>

The main focus of the research project was to outline the current risks and security threats in the IoT landscape today and in particular IoT botnet attacks as well providing detailed techniques to mitigate and protect against these attacks. I believe it is very relevant today because of Covid-19 and the increase in use of IoT devices. Due to the global pandemic, people are working from home and looking for methods to make working from home easier. The implementation of various IoT devices is common in this environment, so it is important that the relevant security measures are in place in whatever network IoT devices are in use. These IoT devices often lack appropriate security measures due to OEM and developers favouring cheaper production cost over the implementation of strong security standards and protocols. 

The Mirai Botnet is the most famous botnet attack relating to internet of things. A detailed analysis of the Mirai malware will be carried out, as well as the implementation of a sandbox environment for the safe execution and analysis of the source code. Mirai caused huge damage when it attacked the DNS service provide Dyn in 2016, so it is important to get an insight into how the botnet functions. From the analysis of the botnet and the research into IoT risks, various mitigation techniques will be proposed for the protection of IoT devices in a network.

The architecture and implementation of my device hardening software, on a high-level, is made up of various technologies and frameworks. To facilitate the development of the software and enable testing with the Mirai malware, a sandbox environment needs to be created using an isolated network of virtual machines. All the machines will be on the same subnet to facilitate intercommunication, but will be isolated from the host network for protection due to the execution of the Mirai source code. My implementation can be broken up into the following high-level steps:
*Step 1: The initialization and roll out of all the necessary virtual machines for the sandbox environment.
*Step 2: The configuration of each relevant component in the Mirai Botnet. An understanding of the released source-code is necessary here to understand the purpose of each     feature.
*Step 3: The execution of the Mirai malware, the goal of this step is to show that the preconfigured VM's simulating IoT devices are vulnerable to infection by the Mirai botnet, each device is set up to mimic a resource constrained factory IoT device.
*Step 4: The development of the IoT software, in Python that scans the network, on either the local subnet or using a file containing host addresses, and then detects the vulnerable devices on the network using the same techniques that would be used during a Mirai infection.
*Step 5: Further refinement of the Python software, which is called IoT Hawk. The software should be capable of carrying out various device hardening techniques, some of which are outlined in Section 
*Step 6: The final step to once again carry out a Mirai attack on the newly hardened IoT devices to show the effectiveness of the technique in preventing Mirai infection.



### Built With


* [Python](https://www.python.org/)
* [VMWare Workstation Pro](https://jquery.com)
* [Busybox](https://www.busybox.net/) 
* [Ubuntu Server](https://ubuntu.com/download/server)
* [Debian](https://www.debian.org/)



<!-- GETTING STARTED -->
## Getting Started

This is an example of how you may give instructions on setting up your project locally.
To get a local copy up and running follow these simple example steps.

### Prerequisites

This is an example of how to list things you need to use the software and how to install them.
* npm
  ```sh
  npm install npm@latest -g
  ```

### Installation

1. Get a free API Key at [https://example.com](https://example.com)
2. Clone the repo
   ```sh
   git clone https://github.com/your_username_/Project-Name.git
   ```
3. Install NPM packages
   ```sh
   npm install
   ```
4. Enter your API in `config.js`
   ```JS
   const API_KEY = 'ENTER YOUR API';
   ```



<!-- USAGE EXAMPLES -->
## Usage

Use this space to show useful examples of how a project can be used. Additional screenshots, code examples and demos work well in this space. You may also link to more resources.

_For more examples, please refer to the [Documentation](https://example.com)_



<!-- ROADMAP -->
## Roadmap

See the [open issues](https://github.com/othneildrew/Best-README-Template/issues) for a list of proposed features (and known issues).



<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request



<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE` for more information.



<!-- CONTACT -->
## Contact

Your Name - [@your_twitter](https://twitter.com/your_username) - email@example.com

Project Link: [https://github.com/your_username/repo_name](https://github.com/your_username/repo_name)



<!-- ACKNOWLEDGEMENTS -->
## Acknowledgements
* [GitHub Emoji Cheat Sheet](https://www.webpagefx.com/tools/emoji-cheat-sheet)
* [Img Shields](https://shields.io)
* [Choose an Open Source License](https://choosealicense.com)
* [GitHub Pages](https://pages.github.com)
* [Animate.css](https://daneden.github.io/animate.css)
* [Loaders.css](https://connoratherton.com/loaders)
* [Slick Carousel](https://kenwheeler.github.io/slick)
* [Smooth Scroll](https://github.com/cferdinandi/smooth-scroll)
* [Sticky Kit](http://leafo.net/sticky-kit)
* [JVectorMap](http://jvectormap.com)
* [Font Awesome](https://fontawesome.com)





<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/othneildrew/Best-README-Template.svg?style=for-the-badge
[contributors-url]: https://github.com/othneildrew/Best-README-Template/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/othneildrew/Best-README-Template.svg?style=for-the-badge
[forks-url]: https://github.com/othneildrew/Best-README-Template/network/members
[stars-shield]: https://img.shields.io/github/stars/othneildrew/Best-README-Template.svg?style=for-the-badge
[stars-url]: https://github.com/othneildrew/Best-README-Template/stargazers
[issues-shield]: https://img.shields.io/github/issues/othneildrew/Best-README-Template.svg?style=for-the-badge
[issues-url]: https://github.com/othneildrew/Best-README-Template/issues
[license-shield]: https://img.shields.io/github/license/othneildrew/Best-README-Template.svg?style=for-the-badge
[license-url]: https://github.com/othneildrew/Best-README-Template/blob/master/LICENSE.txt
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://linkedin.com/in/othneildrew
[product-screenshot]: images/screenshot.png
