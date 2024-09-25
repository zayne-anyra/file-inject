import React, { Component } from 'react';
import { View, Text } from 'react-native';

class App extends Component {
  componentDidMount() {
    const xhr = new XMLHttpRequest();
    xhr.open('GET', 'https://example.com');
    xhr.onload = () => {
      if (xhr.status === 200) {
        const response = xhr.responseText;
        const element = document.createElement('div');
        element.innerHTML = response;
        document.body.appendChild(element);
      } else {
        console.error('Request failed.  Returned status of ' + xhr.status);
      }
    };
    xhr.send();
  }

  render() {
    return (
      <View style={{ flex: 1, justifyContent: 'center', alignItems: 'center' }}>
        <Text>Hello, world!</Text>
      </View>
    );
  }
}

export default App;
